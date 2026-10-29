#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "store_internal.h"

#define PART_SKIP	0
#define PART_TEXT	1
#define PART_MULTI	2
#define PART_MESSAGE	3

#define ENC_IDENTITY	0
#define ENC_BASE64	1
#define ENC_QP		2

struct body_key {
	int		 op;
	char		*fold;
	size_t		*fail;
	size_t		 len;
	char		*hit;
};

struct body_walk {
	struct body_key	*keys;
	uint32_t	 nkeys;
	uint32_t	 left;
};

static const char *const month_names[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

static int	 ascii_lower(int);
static int	 ci_contains(const char *, size_t, const char *, size_t);
static int	 b64_value(int);
static int	 hex_value(int);
static size_t	 decode_word(const char *, size_t, char *);
static size_t	 encoded_word_len(const char *, size_t);
static char	*decode_value(const char *, size_t, size_t *);
static int	 date_fws(int);
static int	 date_field_day(const char *, size_t, int64_t *);
static int	 read_header(int, const char *, int, char **, size_t *);
static int	 match_addresses(const char *, size_t, const char *, size_t);
static int	 match_leaf(const char *, size_t,
		    const struct imsg_parser_leaf *, const char *);
static void	 kmp_prepare(const char *, size_t, char *, size_t *);
static int	 kmp_contains(const char *, size_t, const char *,
		    const size_t *, size_t);
static size_t	 decode_b64(const char *, size_t, char *);
static size_t	 decode_qp(const char *, size_t, char *);
static void	 scan_text(struct body_walk *, const char *, size_t, int);
static int	 scan_header(struct body_walk *, const char *, size_t);
static int	 scan_body(struct body_walk *, const char *, size_t, int);
static int	 part_type(const char *, size_t, int, char *, size_t,
		    int *, int *);
static int	 next_delimiter(const char *, size_t, const char *,
		    size_t, size_t *, size_t *, int *);
static int	 walk_multipart(struct body_walk *, int, const char *,
		    size_t, const char *, int);
static int	 walk_entity(struct body_walk *, int, const char *, size_t,
		    const char *, size_t, int);
static int	 match_body(const char *, size_t, size_t,
		    const struct imsg_parser_leaf *, uint32_t, const char *,
		    char *);

/*
 * SEARCH folds case in the ASCII range only.
 */
static int
ascii_lower(int c)
{
	return ((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
}

static int
ci_contains(const char *hay, size_t haylen, const char *needle,
    size_t needlelen)
{
	size_t	 i, j;

	if (needlelen == 0)
		return (1);
	if (needlelen > haylen)
		return (0);
	for (i = 0; i + needlelen <= haylen; i++) {
		for (j = 0; j < needlelen; j++) {
			if (ascii_lower((unsigned char)hay[i + j]) !=
			    ascii_lower((unsigned char)needle[j]))
				break;
		}
		if (j == needlelen)
			return (1);
	}
	return (0);
}

static int
b64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+')
		return (62);
	if (c == '/')
		return (63);
	return (-1);
}

static int
hex_value(int c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	return (-1);
}

/*
 * RFC 2047 section 2 encoded-word.
 */
static size_t
decode_word(const char *w, size_t len, char *out)
{
	unsigned int	 bits = 0;
	const char	*p, *end;
	size_t		 n = 0;
	int		 enc, nbits = 0, v, hi, lo;

	if (len < 8 || w[0] != '=' || w[1] != '?' || w[len - 2] != '?' ||
	    w[len - 1] != '=')
		return (0);
	end = w + len - 2;
	if ((p = memchr(w + 2, '?', len - 4)) == NULL || p == w + 2)
		return (0);
	if (p + 3 > end || p[2] != '?')
		return (0);
	enc = ascii_lower((unsigned char)p[1]);
	for (p += 3; p < end; p++) {
		if (enc == 'b') {
			if (*p == '=')
				break;
			if ((v = b64_value((unsigned char)*p)) == -1)
				return (0);
			/* Twelve bits hold what one character can leave. */
			bits = ((bits << 6) | (unsigned int)v) & 0xfff;
			if ((nbits += 6) >= 8) {
				nbits -= 8;
				out[n++] = (char)((bits >> nbits) & 0xff);
			}
		} else if (enc == 'q') {
			if (*p == '_')
				out[n++] = ' ';
			else if (*p == '=') {
				if (p + 2 >= end ||
				    (hi = hex_value((unsigned char)p[1])) ==
				    -1 ||
				    (lo = hex_value((unsigned char)p[2])) == -1)
					return (0);
				out[n++] = (char)(hi << 4 | lo);
				p += 2;
			} else
				out[n++] = *p;
		} else
			return (0);
	}
	return (n);
}

static size_t
encoded_word_len(const char *s, size_t len)
{
	size_t	 i, cs;

	if (len < 8 || s[0] != '=' || s[1] != '?')
		return (0);
	for (i = 2; i < len && s[i] != '?'; i++) {
		if (s[i] == ' ' || s[i] == '\t')
			return (0);
	}
	cs = i;
	if (cs == 2 || cs + 3 >= len || s[cs + 2] != '?')
		return (0);
	for (i = cs + 3; i + 1 < len; i++) {
		if (s[i] == ' ' || s[i] == '\t')
			return (0);
		if (s[i] == '?' && s[i + 1] == '=')
			return (i + 2);
	}
	return (0);
}

/*
 * Unfold the value and decode its encoded-words.
 */
static char *
decode_value(const char *v, size_t vlen, size_t *outlen)
{
	size_t	 i, n = 0, ulen = 0, wlen, dn, gap = 0;
	char	*out, *unf;
	int	 after_word = 0;

	if ((unf = malloc(vlen + 1)) == NULL)
		return (NULL);
	for (i = 0; i < vlen; i++) {
		if (v[i] != '\r' && v[i] != '\n')
			unf[ulen++] = v[i];
	}
	/* Decoding never lengthens a word, so ulen is enough. */
	if ((out = malloc(ulen + 1)) == NULL) {
		free(unf);
		return (NULL);
	}
	for (i = 0; i < ulen; ) {
		if (unf[i] == ' ' || unf[i] == '\t') {
			out[n++] = unf[i++];
			gap++;
			continue;
		}
		/* A failed word leaves octets past n, overwritten below. */
		if ((wlen = encoded_word_len(unf + i, ulen - i)) > 0 &&
		    (dn = decode_word(unf + i, wlen, out + n)) > 0) {
			/* White space between two encoded-words is dropped. */
			if (after_word) {
				memmove(out + n - gap, out + n, dn);
				n -= gap;
			}
			n += dn;
			i += wlen;
			after_word = 1;
			gap = 0;
			continue;
		}
		out[n++] = unf[i++];
		after_word = 0;
		gap = 0;
	}
	free(unf);
	*outlen = n;
	return (out);
}

/*
 * CR and LF may also separate date tokens.
 */
static int
date_fws(int c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

/*
 * Return the day's UTC midnight, ignoring time and zone.
 */
static int
date_field_day(const char *v, size_t vlen, int64_t *out)
{
	const char	*p = v, *end = v + vlen;
	struct tm	 tm;
	time_t		 t;
	int		 day = 0, year = 0, mon, nd = 0, ny = 0;

	while (p < end && date_fws((unsigned char)*p))
		p++;
	/* The day of the week is optional. */
	if (p < end && ascii_lower((unsigned char)*p) >= 'a' &&
	    ascii_lower((unsigned char)*p) <= 'z') {
		while (p < end && *p != ',')
			p++;
		if (p == end)
			return (-1);
		p++;
		while (p < end && date_fws((unsigned char)*p))
			p++;
	}
	for (; p < end && *p >= '0' && *p <= '9' && nd < 2; p++, nd++)
		day = day * 10 + (*p - '0');
	if (nd == 0 || p == end || !date_fws((unsigned char)*p))
		return (-1);
	while (p < end && date_fws((unsigned char)*p))
		p++;
	if (end - p < 3)
		return (-1);
	for (mon = 0; mon < 12; mon++) {
		if (strncasecmp(p, month_names[mon], 3) == 0)
			break;
	}
	if (mon == 12)
		return (-1);
	p += 3;
	if (p == end || !date_fws((unsigned char)*p))
		return (-1);
	while (p < end && date_fws((unsigned char)*p))
		p++;
	for (; p < end && *p >= '0' && *p <= '9' && ny < 4; p++, ny++)
		year = year * 10 + (*p - '0');
	if (ny < 2 || day < 1 || day > 31)
		return (-1);
	if (ny == 2)
		year += (year < 50) ? 2000 : 1900;
	else if (ny == 3)
		year += 1900;
	if (year < 1970)
		return (-1);

	memset(&tm, 0, sizeof(tm));
	tm.tm_mday = day;
	tm.tm_mon = mon;
	tm.tm_year = year - 1900;
	if ((t = timegm(&tm)) == (time_t)-1)
		return (-1);
	*out = (int64_t)t;
	return (0);
}

/*
 * Read the header, or with whole set the message.  Read at most attachment
 * max octets.
 */
static int
read_header(int fd, const char *basename, int whole, char **buf_out,
    size_t *len_out)
{
	struct stat	 st;
	ssize_t		 n;
	size_t		 len = 0, size = 0, hdrend, limit;
	char		*buf = NULL, *nbuf;

	if (whole && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > (off_t)bodystructure_read_max)
		goto toolarge;
	/* One spare octet detects a header over the cap. */
	limit = (size_t)bodystructure_read_max + 1;
	for (;;) {
		if (len == size) {
			if (size == limit)
				break;
			size = size == 0 ? STORE_READ_BLOCK : size * 2;
			if (size > limit)
				size = limit;
			if ((nbuf = realloc(buf, size)) == NULL) {
				log_warn("realloc SEARCH header");
				free(buf);
				return (-1);
			}
			buf = nbuf;
		}
		if ((n = read(fd, buf + len, size - len)) == -1) {
			if (errno == EINTR)
				continue;
			log_warn("read message header (%s)", basename);
			free(buf);
			return (-1);
		}
		if (n == 0)
			break;
		len += (size_t)n;
		if (!whole && find_header_body_split(buf, len, &hdrend) == 0) {
			len = hdrend;
			break;
		}
	}
	if (len > bodystructure_read_max)
		goto toolarge;
	*buf_out = buf;
	*len_out = len;
	return (0);

toolarge:
	log_warnx("message %s %s %u bytes, SEARCH cannot check it", basename,
	    whole ? "is over" : "has no header end within",
	    bodystructure_read_max);
	free(buf);
	return (-1);
}

/*
 * Match addresses as ENVELOPE shows them, ignoring group names.
 */
static int
match_addresses(const char *v, size_t vlen, const char *needle,
    size_t needlelen)
{
	struct address	 a;
	size_t		 i, ulen = 0, pos = 0, toklen, declen;
	char		*unf, *tok, *dec;
	int		 hit = 0, ingroup = 0, kind;

	if ((unf = malloc(vlen + 1)) == NULL)
		return (-1);
	for (i = 0; i < vlen; i++) {
		if (v[i] != '\r' && v[i] != '\n')
			unf[ulen++] = v[i];
	}
	ulen = address_uncomment(unf, ulen);

	while (hit == 0 && (kind = address_list_next(unf, ulen, &pos,
	    &ingroup, &tok, &toklen)) != 0) {
		if (kind != ADDR_MAILBOX ||
		    address_split(tok, toklen, &a) == -1)
			continue;
		/* Cooking only shortens, so mailbox@host fits where it was. */
		a.mailbox[a.mailboxlen] = '@';
		memmove(a.mailbox + a.mailboxlen + 1, a.host, a.hostlen);
		hit = ci_contains(a.mailbox, a.mailboxlen + 1 + a.hostlen,
		    needle, needlelen);
		if (hit || a.name == NULL)
			continue;
		if ((dec = decode_value(a.name, a.namelen, &declen)) == NULL) {
			hit = -1;
			break;
		}
		hit = ci_contains(dec, declen, needle, needlelen);
		free(dec);
	}
	free(unf);
	return (hit);
}

static int
match_leaf(const char *hdr, size_t hdrlen,
    const struct imsg_parser_leaf *l, const char *pool)
{
	const char	*name, *val, *want;
	int64_t		 day;
	size_t		 namelen, vallen, wantlen, off = 0, dlen;
	char		*dec;
	int		 hit = 0, date = 0, addr = 0;

	switch (l->op) {
	case SEARCH_OP_SUBJECT:
		want = "Subject";
		wantlen = 7;
		break;
	case SEARCH_OP_HEADER:
		want = pool + l->name_off;
		wantlen = l->name_len;
		break;
	case SEARCH_OP_SENTBEFORE:
	case SEARCH_OP_SENTON:
	case SEARCH_OP_SENTSINCE:
		want = "Date";
		wantlen = 4;
		date = 1;
		break;
	case SEARCH_OP_FROM:
		want = "From";
		wantlen = 4;
		addr = 1;
		break;
	case SEARCH_OP_TO:
		want = "To";
		wantlen = 2;
		addr = 1;
		break;
	case SEARCH_OP_CC:
		want = "Cc";
		wantlen = 2;
		addr = 1;
		break;
	case SEARCH_OP_BCC:
		want = "Bcc";
		wantlen = 3;
		addr = 1;
		break;
	default:
		return (0);
	}

	/* As in ENVELOPE, the first Date or Subject counts. */
	while (!hit && header_next_field(hdr, hdrlen, &off, &name, &namelen,
	    &val, &vallen) == 1) {
		if (namelen != wantlen || strncasecmp(name, want, wantlen) != 0)
			continue;
		if (date) {
			if (date_field_day(val, vallen, &day) == -1)
				return (0);
			if (l->op == SEARCH_OP_SENTBEFORE)
				return (day < l->num);
			if (l->op == SEARCH_OP_SENTON)
				return (day == l->num);
			return (day >= l->num);
		}
		if (addr) {
			hit = match_addresses(val, vallen, pool + l->str_off,
			    l->str_len);
			if (hit == -1)
				return (-1);
			continue;
		}
		if ((dec = decode_value(val, vallen, &dlen)) == NULL)
			return (-1);
		hit = ci_contains(dec, dlen, pool + l->str_off, l->str_len);
		free(dec);
		if (l->op == SEARCH_OP_SUBJECT)
			break;
	}
	return (hit);
}

/*
 * Knuth-Morris-Pratt keeps crafted input to linear time.
 */
static void
kmp_prepare(const char *needle, size_t len, char *fold, size_t *fail)
{
	size_t	 i, k = 0;

	for (i = 0; i < len; i++)
		fold[i] = (char)ascii_lower((unsigned char)needle[i]);
	if (len > 0)
		fail[0] = 0;
	for (i = 1; i < len; i++) {
		while (k > 0 && fold[i] != fold[k])
			k = fail[k - 1];
		if (fold[i] == fold[k])
			k++;
		fail[i] = k;
	}
}

static int
kmp_contains(const char *hay, size_t haylen, const char *fold,
    const size_t *fail, size_t len)
{
	size_t	 i, k = 0;
	int	 c;

	if (len == 0)
		return (1);
	for (i = 0; i < haylen; i++) {
		c = ascii_lower((unsigned char)hay[i]);
		while (k > 0 && c != (unsigned char)fold[k])
			k = fail[k - 1];
		if (c == (unsigned char)fold[k] && ++k == len)
			return (1);
	}
	return (0);
}

/*
 * RFC 2045 section 6.8 ignores characters outside the alphabet.
 */
static size_t
decode_b64(const char *in, size_t len, char *out)
{
	unsigned int	 bits = 0;
	size_t		 i, n = 0;
	int		 nbits = 0, v;

	for (i = 0; i < len && in[i] != '='; i++) {
		if ((v = b64_value((unsigned char)in[i])) == -1)
			continue;
		bits = ((bits << 6) | (unsigned int)v) & 0xfff;
		if ((nbits += 6) >= 8) {
			nbits -= 8;
			out[n++] = (char)((bits >> nbits) & 0xff);
		}
	}
	return (n);
}

/*
 * Decode quoted-printable.  An "=" that is neither a soft line break nor a
 * hex pair is kept as it is.
 */
static size_t
decode_qp(const char *in, size_t len, char *out)
{
	size_t	 i, j, n = 0;
	int	 hi, lo;

	for (i = 0; i < len; i++) {
		if (in[i] != '=') {
			out[n++] = in[i];
			continue;
		}
		for (j = i + 1; j < len && (in[j] == ' ' || in[j] == '\t');
		    j++)
			;
		if (j < len && in[j] == '\n') {
			i = j;
			continue;
		}
		if (j + 1 < len && in[j] == '\r' && in[j + 1] == '\n') {
			i = j + 1;
			continue;
		}
		if (i + 2 < len &&
		    (hi = hex_value((unsigned char)in[i + 1])) != -1 &&
		    (lo = hex_value((unsigned char)in[i + 2])) != -1) {
			out[n++] = (char)(hi << 4 | lo);
			i += 2;
			continue;
		}
		out[n++] = in[i];
	}
	return (n);
}

static void
scan_text(struct body_walk *w, const char *t, size_t len, int header)
{
	struct body_key	*k;
	uint32_t	 i;

	for (i = 0; i < w->nkeys && w->left > 0; i++) {
		k = &w->keys[i];
		if (*k->hit || (header && k->op != SEARCH_OP_TEXT))
			continue;
		if (kmp_contains(t, len, k->fold, k->fail, k->len)) {
			*k->hit = 1;
			w->left--;
		}
	}
}

/*
 * TEXT matches every header field, MIME part headers included.
 */
static int
scan_header(struct body_walk *w, const char *hdr, size_t hdrlen)
{
	const char	*name, *val;
	uint32_t	 i;
	size_t		 namelen, vallen, dlen, off = 0;
	char		*dec, *line;

	for (i = 0; i < w->nkeys; i++) {
		if (*w->keys[i].hit == 0 && w->keys[i].op == SEARCH_OP_TEXT)
			break;
	}
	if (i == w->nkeys)
		return (0);

	while (w->left > 0 && header_next_field(hdr, hdrlen, &off, &name,
	    &namelen, &val, &vallen) == 1) {
		if ((dec = decode_value(val, vallen, &dlen)) == NULL)
			return (-1);
		if ((line = malloc(namelen + 2 + dlen)) == NULL) {
			free(dec);
			return (-1);
		}
		memcpy(line, name, namelen);
		memcpy(line + namelen, ": ", 2);
		memcpy(line + namelen + 2, dec, dlen);
		scan_text(w, line, namelen + 2 + dlen, 1);
		free(line);
		free(dec);
	}
	return (0);
}

static int
scan_body(struct body_walk *w, const char *body, size_t len, int enc)
{
	size_t	 n;
	char	*out;

	if (enc == ENC_IDENTITY) {
		scan_text(w, body, len, 0);
		return (0);
	}
	/* Neither decoding lengthens its input. */
	if ((out = malloc(len + 1)) == NULL)
		return (-1);
	n = (enc == ENC_BASE64) ? decode_b64(body, len, out) :
	    decode_qp(body, len, out);
	scan_text(w, out, n, 0);
	free(out);
	return (0);
}

static int
part_type(const char *hdr, size_t hdrlen, int digest, char *boundary,
    size_t boundarysize, int *enc, int *subdigest)
{
	size_t	 vallen = 0, pos = 0;
	char	*val = NULL, type[64], subtype[64], attr[64], value[256];
	int	 kind, has_boundary = 0;

	*enc = ENC_IDENTITY;
	*subdigest = 0;
	if (extract_header_field(hdr, hdrlen, "Content-Transfer-Encoding",
	    &val, &vallen) == 0) {
		while (vallen > 0 && (val[vallen - 1] == ' ' ||
		    val[vallen - 1] == '\t'))
			vallen--;
		if (vallen == 6 && strncasecmp(val, "base64", 6) == 0)
			*enc = ENC_BASE64;
		else if (vallen == 16 &&
		    strncasecmp(val, "quoted-printable", 16) == 0)
			*enc = ENC_QP;
		else if (!(vallen == 0 ||
		    (vallen == 4 && (strncasecmp(val, "7bit", 4) == 0 ||
		    strncasecmp(val, "8bit", 4) == 0)) ||
		    (vallen == 6 && strncasecmp(val, "binary", 6) == 0))) {
			/* An unknown encoding is application/octet-stream. */
			free(val);
			return (PART_SKIP);
		}
		free(val);
	}

	/* No type means text/plain, or message/rfc822 in a digest. */
	if (extract_header_field(hdr, hdrlen, "Content-Type", &val,
	    &vallen) == -1 || vallen == 0) {
		free(val);
		return (digest ? PART_MESSAGE : PART_TEXT);
	}
	if (mime_read_token_or_qstring(val, vallen, &pos, type,
	    sizeof(type)) == -1 || pos >= vallen || val[pos++] != '/' ||
	    mime_read_token_or_qstring(val, vallen, &pos, subtype,
	    sizeof(subtype)) == -1) {
		free(val);
		return (PART_TEXT);
	}
	for (;;) {
		while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
			pos++;
		if (pos >= vallen || val[pos++] != ';')
			break;
		while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
			pos++;
		if (mime_read_token_or_qstring(val, vallen, &pos, attr,
		    sizeof(attr)) == -1)
			break;
		while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
			pos++;
		if (pos >= vallen || val[pos++] != '=')
			break;
		while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
			pos++;
		if (mime_read_token_or_qstring(val, vallen, &pos, value,
		    sizeof(value)) == -1)
			break;
		if (strcasecmp(attr, "boundary") == 0 &&
		    strlcpy(boundary, value, boundarysize) < boundarysize)
			has_boundary = 1;
	}
	free(val);

	if (strcasecmp(type, "multipart") == 0) {
		/* A multipart without a boundary is invalid. */
		if (!has_boundary)
			return (PART_TEXT);
		*subdigest = strcasecmp(subtype, "digest") == 0;
		kind = PART_MULTI;
	} else if (strcasecmp(type, "message") == 0)
		kind = (strcasecmp(subtype, "rfc822") == 0 ||
		    strcasecmp(subtype, "global") == 0) ? PART_MESSAGE :
		    PART_TEXT;
	else
		kind = strcasecmp(type, "text") == 0 ? PART_TEXT : PART_SKIP;
	/* Multipart and message bodies are 7bit, 8bit or binary. */
	if (kind != PART_TEXT)
		*enc = ENC_IDENTITY;
	return (kind);
}

static int
next_delimiter(const char *body, size_t len, const char *delim,
    size_t dlen, size_t *pos, size_t *start, int *closing)
{
	const char	*nl;
	size_t		 i = *pos, after;

	while (i < len) {
		if (len - i >= dlen && memcmp(body + i, delim, dlen) == 0) {
			after = i + dlen;
			*closing = 0;
			if (len - after >= 2 && body[after] == '-' &&
			    body[after + 1] == '-') {
				*closing = 1;
				after += 2;
			}
			while (after < len &&
			    (body[after] == ' ' || body[after] == '\t'))
				after++;
			if (after == len || body[after] == '\n' ||
			    (body[after] == '\r' && after + 1 < len &&
			    body[after + 1] == '\n')) {
				if (after < len)
					after += body[after] == '\r' ? 2 : 1;
				*start = i;
				*pos = after;
				return (1);
			}
		}
		if ((nl = memchr(body + i, '\n', len - i)) == NULL)
			break;
		i = (size_t)(nl - body) + 1;
	}
	return (0);
}

/*
 * The message size bounds the number of parts.
 */
static int
walk_multipart(struct body_walk *w, int depth, const char *body,
    size_t len, const char *boundary, int digest)
{
	size_t	 dlen, pos = 0, dstart, pstart = 0, pend, phdr;
	char	 delim[2 + MIME_BOUNDARY_MAX + 1];
	int	 closing, inpart = 0, ret, found;

	ret = snprintf(delim, sizeof(delim), "--%s", boundary);
	if (ret < 0 || (size_t)ret >= sizeof(delim))
		fatalx("%s: boundary too long", __func__);
	dlen = (size_t)ret;
	for (;;) {
		found = next_delimiter(body, len, delim, dlen, &pos, &dstart,
		    &closing);
		if (!found)
			dstart = len;
		if (inpart) {
			/* A delimiter owns the line end before it. */
			pend = dstart;
			if (pend >= pstart + 2 && body[pend - 2] == '\r' &&
			    body[pend - 1] == '\n')
				pend -= 2;
			else if (pend >= pstart + 1 && body[pend - 1] == '\n')
				pend--;
			if (pend == pstart)
				phdr = 0;
			else if (find_header_body_split(body + pstart,
			    pend - pstart, &phdr) == -1)
				phdr = pend - pstart;
			if (walk_entity(w, depth + 1, body + pstart, phdr,
			    body + pstart + phdr, pend - pstart - phdr,
			    digest) == -1)
				return (-1);
		}
		/* A truncated multipart ends where the message does. */
		if (!found || closing)
			return (0);
		pstart = pos;
		inpart = 1;
	}
}

static int
walk_entity(struct body_walk *w, int depth, const char *hdr, size_t hdrlen,
    const char *body, size_t bodylen, int digest)
{
	size_t	 ih;
	char	 boundary[MIME_BOUNDARY_MAX + 1];
	int	 enc, subdigest;

	if (w->left == 0)
		return (0);
	/* Past the BODYSTRUCTURE depth, SEARCH cannot check. */
	if (depth > MIME_MAX_DEPTH)
		return (-1);
	if (scan_header(w, hdr, hdrlen) == -1)
		return (-1);
	switch (part_type(hdr, hdrlen, digest, boundary, sizeof(boundary),
	    &enc, &subdigest)) {
	case PART_MULTI:
		return (walk_multipart(w, depth, body, bodylen, boundary,
		    subdigest));
	case PART_MESSAGE:
		if (bodylen == 0)
			ih = 0;
		else if (find_header_body_split(body, bodylen, &ih) == -1)
			ih = bodylen;
		return (walk_entity(w, depth + 1, body, ih, body + ih,
		    bodylen - ih, 0));
	case PART_TEXT:
		return (scan_body(w, body, bodylen, enc));
	default:
		return (0);
	}
}

/*
 * BODY and TEXT search only text and message parts.
 */
static int
match_body(const char *msg, size_t hdrlen, size_t len,
    const struct imsg_parser_leaf *leaves, uint32_t nleaves,
    const char *pool, char *out)
{
	struct body_walk	 w;
	struct body_key		*k;
	uint32_t		 i;
	int			 rc = -1;

	memset(&w, 0, sizeof(w));
	if ((w.keys = calloc(nleaves, sizeof(*w.keys))) == NULL)
		return (-1);
	for (i = 0; i < nleaves; i++) {
		if (leaves[i].op != SEARCH_OP_BODY &&
		    leaves[i].op != SEARCH_OP_TEXT)
			continue;
		out[i] = 0;
		/* The empty string is a substring. */
		if (leaves[i].str_len == 0) {
			out[i] = 1;
			continue;
		}
		k = &w.keys[w.nkeys++];
		k->op = leaves[i].op;
		k->len = leaves[i].str_len;
		k->hit = &out[i];
		if ((k->fold = malloc(k->len)) == NULL ||
		    (k->fail = calloc(k->len, sizeof(*k->fail))) == NULL)
			goto done;
		kmp_prepare(pool + leaves[i].str_off, k->len, k->fold,
		    k->fail);
		w.left++;
	}
	rc = walk_entity(&w, 0, msg, hdrlen, msg + hdrlen, len - hdrlen, 0);
done:
	for (i = 0; i < w.nkeys; i++) {
		free(w.keys[i].fold);
		free(w.keys[i].fail);
	}
	free(w.keys);
	return (rc);
}

int
search_match(int fd, const char *basename,
    const struct imsg_parser_leaf *leaves, uint32_t nleaves,
    const char *pool, char **buf_out, uint32_t *len_out)
{
	uint32_t	 i;
	size_t		 hdrlen, len;
	char		*hdr, *out;
	int		 m, whole = 0;

	*buf_out = NULL;
	*len_out = 0;
	for (i = 0; i < nleaves; i++) {
		if (leaves[i].op == SEARCH_OP_BODY ||
		    leaves[i].op == SEARCH_OP_TEXT)
			whole = 1;
	}
	if (nleaves == 0 || read_header(fd, basename, whole, &hdr, &len) == -1)
		return (-1);
	/* A message with no blank line is all header. */
	if (!whole || find_header_body_split(hdr, len, &hdrlen) == -1)
		hdrlen = len;
	if ((out = malloc(nleaves)) == NULL) {
		free(hdr);
		return (-1);
	}
	for (i = 0; i < nleaves; i++) {
		if (leaves[i].op == SEARCH_OP_BODY ||
		    leaves[i].op == SEARCH_OP_TEXT)
			continue;
		if ((m = match_leaf(hdr, hdrlen, &leaves[i], pool)) == -1) {
			free(out);
			free(hdr);
			return (-1);
		}
		out[i] = (char)m;
	}
	if (whole && match_body(hdr, hdrlen, len, leaves, nleaves, pool,
	    out) == -1) {
		free(out);
		free(hdr);
		return (-1);
	}
	free(hdr);
	*buf_out = out;
	*len_out = nleaves;
	return (0);
}
