#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "store_internal.h"

static size_t	 quoted_end(const char *, size_t, size_t);
static size_t	 unquoted_find(const char *, size_t, size_t, const char *);
static int	 address_list_add(char *, size_t, size_t *, char *, size_t,
		    int *);
static int	 envbuf_append_address_fields(char *, size_t, size_t *,
		    const char *, size_t, const char *, int *);
static int	 envelope_from_header(const char *, size_t, char *, size_t,
		    size_t *);
static size_t	 address_cook(char *, size_t, int);
static int	 envbuf_append_one_address(char *, size_t, size_t *,
		    const struct address *);
static int	 append_field_nstring(char *, size_t, size_t *, const char *,
		    size_t, const char *);
static int	 build_part_structure(int, int *, const char *, size_t,
		    const char *, size_t, char *, size_t, size_t *);

int
envbuf_append(char *buf, size_t bufsize, size_t *outlen, const char *data,
    size_t datalen)
{
	/* Subtract, since adding could wrap near SIZE_MAX. */
	if (*outlen > bufsize || datalen > bufsize - *outlen)
		return (-1);
	memcpy(buf + *outlen, data, datalen);
	*outlen += datalen;
	return (0);
}

int
envbuf_append_str(char *buf, size_t bufsize, size_t *outlen, const char *s)
{
	return (envbuf_append(buf, bufsize, outlen, s, strlen(s)));
}

int
envbuf_append_nstring(char *buf, size_t bufsize, size_t *outlen,
    const char *val, size_t vallen)
{
	size_t	 save = *outlen;
	size_t	 i;
	char	 c;

	if (val == NULL)
		return (envbuf_append_str(buf, bufsize, outlen, "NIL"));

	if (envbuf_append(buf, bufsize, outlen, "\"", 1) == -1)
		goto fail;
	for (i = 0; i < vallen; i++) {
		c = val[i];

		/* A quoted string cannot carry these. */
		if (c == '\0' || c == '\r' || c == '\n')
			c = ' ';
		if ((c == '"' || c == '\\') &&
		    envbuf_append(buf, bufsize, outlen, "\\", 1) == -1)
			goto fail;
		if (envbuf_append(buf, bufsize, outlen, &c, 1) == -1)
			goto fail;
	}
	if (envbuf_append(buf, bufsize, outlen, "\"", 1) == -1)
		goto fail;
	return (0);

fail:
	*outlen = save;
	return (-1);
}

static size_t
quoted_end(const char *s, size_t len, size_t i)
{
	for (i++; i < len; i++) {
		if (s[i] == '\\' && i + 1 < len)
			i++;
		else if (s[i] == '"')
			return (i + 1);
	}
	return (len);
}

static size_t
unquoted_find(const char *s, size_t len, size_t i, const char *chars)
{
	while (i < len) {
		if (s[i] == '"')
			i = quoted_end(s, len, i);
		else if (s[i] != '\0' && strchr(chars, s[i]) != NULL)
			return (i);
		else
			i++;
	}
	return (len);
}

/*
 * Replace comments with spaces in place, returning the length.
 */
size_t
address_uncomment(char *s, size_t len)
{
	size_t	 i = 0, n = 0, e;
	int	 depth;

	while (i < len) {
		if (s[i] == '"') {
			e = quoted_end(s, len, i);
			memmove(s + n, s + i, e - i);
			n += e - i;
			i = e;
		} else if (s[i] == '(') {
			for (depth = 0; i < len; i++) {
				if (s[i] == '\\' && i + 1 < len)
					i++;
				else if (s[i] == '(')
					depth++;
				else if (s[i] == ')' && --depth == 0) {
					i++;
					break;
				}
			}
			s[n++] = ' ';
		} else
			s[n++] = s[i++];
	}
	return (n);
}

/*
 * Unquote in place, squeezing white space in a phrase.
 */
static size_t
address_cook(char *s, size_t len, int phrase)
{
	size_t	 i, e, n = 0;
	int	 space = 0;

	for (i = 0; i < len; i++) {
		if (s[i] == ' ' || s[i] == '\t') {
			space = phrase;
			continue;
		}
		if (space && n > 0)
			s[n++] = ' ';
		space = 0;
		if (s[i] != '"') {
			s[n++] = s[i];
			continue;
		}
		for (e = quoted_end(s, len, i), i++; i < e; i++) {
			if (s[i] == '\\' && i + 1 < e)
				i++;
			else if (s[i] == '"')
				break;
			s[n++] = s[i];
		}
	}
	return (n);
}

/*
 * Split a mailbox into its parts in place.  Return -1 if the token is not a
 * mailbox.
 */
int
address_split(char *tok, size_t toklen, struct address *a)
{
	size_t	 speclen = toklen, lt, gt, colon, at, i;
	char	*spec = tok;

	memset(a, 0, sizeof(*a));
	lt = unquoted_find(tok, toklen, 0, "<");
	if (lt < toklen) {
		gt = unquoted_find(tok, toklen, lt + 1, ">");
		if (gt == toklen)
			return (-1);
		spec = tok + lt + 1;
		speclen = gt - lt - 1;
		if ((a->namelen = address_cook(tok, lt, 1)) > 0)
			a->name = tok;
	}
	while (speclen > 0 && (spec[0] == ' ' || spec[0] == '\t')) {
		spec++;
		speclen--;
	}

	/* RFC 5322 section 4.4 obs-route. */
	if (speclen > 0 && spec[0] == '@') {
		colon = unquoted_find(spec, speclen, 0, ":");
		if (colon == speclen)
			return (-1);
		a->route = spec;
		a->routelen = address_cook(spec, colon, 0);
		spec += colon + 1;
		speclen -= colon + 1;
	}

	if (unquoted_find(spec, speclen, 0, ":;<>") < speclen)
		return (-1);
	at = speclen;
	for (i = unquoted_find(spec, speclen, 0, "@"); i < speclen;
	    i = unquoted_find(spec, speclen, i + 1, "@"))
		at = i;
	if (at == speclen || at == 0)
		return (-1);
	a->host = spec + at + 1;
	if ((a->hostlen = address_cook(a->host, speclen - at - 1, 0)) == 0)
		return (-1);
	a->mailbox = spec;
	a->mailboxlen = address_cook(spec, at, 0);
	return (0);
}

/*
 * A group marker has no host.
 */
static int
envbuf_append_one_address(char *buf, size_t bufsize, size_t *outlen,
    const struct address *a)
{
	if (envbuf_append(buf, bufsize, outlen, "(", 1) == -1 ||
	    envbuf_append_nstring(buf, bufsize, outlen, a->name,
	    a->namelen) == -1 ||
	    envbuf_append(buf, bufsize, outlen, " ", 1) == -1 ||
	    envbuf_append_nstring(buf, bufsize, outlen, a->route,
	    a->routelen) == -1 ||
	    envbuf_append(buf, bufsize, outlen, " ", 1) == -1 ||
	    envbuf_append_nstring(buf, bufsize, outlen, a->mailbox,
	    a->mailboxlen) == -1 ||
	    envbuf_append(buf, bufsize, outlen, " ", 1) == -1 ||
	    envbuf_append_nstring(buf, bufsize, outlen, a->host,
	    a->hostlen) == -1)
		return (-1);
	return (envbuf_append(buf, bufsize, outlen, ")", 1));
}

/*
 * Return the next mailbox, group start or group end.
 */
int
address_list_next(char *val, size_t vallen, size_t *pos, int *ingroup,
    char **tok_out, size_t *toklen_out)
{
	size_t	 i = *pos, start;

	while (i < vallen && (val[i] == ' ' || val[i] == '\t' ||
	    val[i] == ','))
		i++;
	if (i == vallen || (*ingroup && val[i] == ';')) {
		*pos = i < vallen ? i + 1 : i;
		if (*ingroup == 0)
			return (0);
		*ingroup = 0;
		return (ADDR_GROUP_END);
	}

	start = i;
	while ((i = unquoted_find(val, vallen, i, *ingroup ? "<,;" :
	    "<,:")) < vallen && val[i] == '<')
		i = unquoted_find(val, vallen, i + 1, ">");

	*tok_out = val + start;
	*toklen_out = i - start;
	while (*toklen_out > 0 && (val[start + *toklen_out - 1] == ' ' ||
	    val[start + *toklen_out - 1] == '\t'))
		(*toklen_out)--;
	if (i < vallen && val[i] == ':') {
		*pos = i + 1;
		*ingroup = 1;
		return (ADDR_GROUP);
	}
	*pos = i < vallen && val[i] == ',' ? i + 1 : i;
	return (ADDR_MAILBOX);
}

static int
address_list_add(char *buf, size_t bufsize, size_t *outlen, char *val,
    size_t vallen, int *any)
{
	struct address	 a;
	size_t		 pos = 0, toklen;
	char		*tok;
	int		 ingroup = 0, kind;

	vallen = address_uncomment(val, vallen);
	while ((kind = address_list_next(val, vallen, &pos, &ingroup, &tok,
	    &toklen)) != 0) {
		memset(&a, 0, sizeof(a));
		if (kind == ADDR_GROUP) {
			a.mailbox = tok;
			a.mailboxlen = address_cook(tok, toklen, 1);
		} else if (kind == ADDR_MAILBOX &&
		    address_split(tok, toklen, &a) == -1)
			continue;
		if (*any == 0 &&
		    envbuf_append(buf, bufsize, outlen, "(", 1) == -1)
			return (-1);
		*any = 1;
		if (envbuf_append_one_address(buf, bufsize, outlen, &a) == -1)
			return (-1);
	}
	return (0);
}

/*
 * Join all occurrences into one list, or give NIL.
 */
static int
envbuf_append_address_fields(char *buf, size_t bufsize, size_t *outlen,
    const char *hdr, size_t hdrlen, const char *field, int *seen)
{
	const char	*name, *val;
	size_t		 flen, off = 0, namelen, vallen;
	size_t		 ulen, i;
	char		*unf;
	int		 any = 0, rc;

	flen = strlen(field);
	*seen = 0;
	while (header_next_field(hdr, hdrlen, &off, &name, &namelen, &val,
	    &vallen) == 1) {
		if (namelen != flen || strncasecmp(name, field, flen) != 0)
			continue;
		if ((unf = malloc(vallen + 1)) == NULL)
			return (-1);
		for (i = ulen = 0; i < vallen; i++) {
			if (val[i] == '\r' || val[i] == '\n')
				continue;
			if (val[i] != ' ' && val[i] != '\t')
				*seen = 1;
			unf[ulen++] = val[i];
		}
		rc = address_list_add(buf, bufsize, outlen, unf, ulen, &any);
		free(unf);
		if (rc == -1)
			return (-1);
	}
	if (any)
		return (envbuf_append(buf, bufsize, outlen, ")", 1));
	return (envbuf_append_str(buf, bufsize, outlen, "NIL"));
}

static int
append_field_nstring(char *out, size_t outsize, size_t *outlen,
    const char *hdrbuf, size_t hdrlen, const char *name)
{
	size_t	 vallen;
	char	*val;
	int	 rc;

	if (extract_header_field(hdrbuf, hdrlen, name, &val, &vallen) == 0) {
		rc = envbuf_append_nstring(out, outsize, outlen, val, vallen);
		free(val);
	} else {
		rc = envbuf_append_nstring(out, outsize, outlen, NULL, 0);
	}
	return (rc);
}

static const char *const fallback_fields[] = {
	"Sender", "Reply-To"
};

static const char *const addr_fields[] = {
	"To", "Cc", "Bcc"
};

/*
 * Sender and Reply-To default to From.
 */
static int
envelope_from_header(const char *hdr, size_t hdrlen, char *out,
    size_t outsize, size_t *outlen)
{
	char		 from_formatted[ENVELOPE_MAX];
	size_t		 from_len = 0, i, save;
	int		 seen;

	if (envbuf_append(out, outsize, outlen, "(", 1) == -1)
		return (-1);

	if (append_field_nstring(out, outsize, outlen, hdr, hdrlen,
	    "Date") == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);
	if (append_field_nstring(out, outsize, outlen, hdr, hdrlen,
	    "Subject") == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	if (envbuf_append_address_fields(from_formatted,
	    sizeof(from_formatted), &from_len, hdr, hdrlen, "From",
	    &seen) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, from_formatted,
	    from_len) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	for (i = 0; i < nitems(fallback_fields); i++) {
		save = *outlen;
		if (envbuf_append_address_fields(out, outsize, outlen, hdr,
		    hdrlen, fallback_fields[i], &seen) == -1)
			return (-1);
		if (!seen) {
			*outlen = save;
			if (envbuf_append(out, outsize, outlen,
			    from_formatted, from_len) == -1)
				return (-1);
		}
		if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
			return (-1);
	}

	for (i = 0; i < nitems(addr_fields); i++) {
		if (envbuf_append_address_fields(out, outsize, outlen, hdr,
		    hdrlen, addr_fields[i], &seen) == -1)
			return (-1);
		if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
			return (-1);
	}

	if (append_field_nstring(out, outsize, outlen, hdr, hdrlen,
	    "In-Reply-To") == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);
	if (append_field_nstring(out, outsize, outlen, hdr, hdrlen,
	    "Message-Id") == -1)
		return (-1);

	return (envbuf_append(out, outsize, outlen, ")", 1));
}

int
build_envelope(int fd, const char *basename, char **buf_out,
    uint32_t *len_out)
{
	uint32_t	 hdrlen = 0;
	size_t		 outlen = 0;
	char		*hdrbuf = NULL;
	char		 out[ENVELOPE_MAX];

	*buf_out = NULL;
	*len_out = 0;

	if (read_header_from_fd(fd, basename, &hdrbuf, &hdrlen) == -1)
		return (-1);
	if (envelope_from_header(hdrbuf, hdrlen, out, sizeof(out),
	    &outlen) == -1) {
		log_warnx("message %s: ENVELOPE not built, skipped", basename);
		free(hdrbuf);
		return (-1);
	}
	free(hdrbuf);

	if ((*buf_out = malloc(outlen)) == NULL) {
		log_warn("malloc ENVELOPE buffer (%s)", basename);
		return (-1);
	}
	memcpy(*buf_out, out, outlen);
	*len_out = (uint32_t)outlen;
	return (0);
}

static const char *const cte_known[] = {
	"7BIT", "8BIT", "BINARY", "BASE64", "QUOTED-PRINTABLE"
};

/*
 * BODYSTRUCTURE without extension data.
 */
static int
build_part_structure(int depth, int *nparts_used, const char *hdr,
    size_t hdrlen, const char *body, size_t bodylen, char *out,
    size_t outsize, size_t *outlen)
{
	struct content_type	 ct;
	char			 encstr[40], numbuf[32];
	char			*idval = NULL, *descval = NULL, *encval = NULL;
	const char		*enc, *pbuf;
	size_t			 part_starts[MIME_MAX_PARTS], plen, phdrend, j;
	size_t			 part_ends[MIME_MAX_PARTS], lines;
	size_t			 idlen = 0, desclen = 0, enclen = 0, ihdr;
	int			 is_text, is_msg, rc, n, i;

	if (depth > MIME_MAX_DEPTH)
		return (-1);
	if (++*nparts_used > MIME_MAX_PARTS)
		return (-1);

	parse_content_type(hdr, hdrlen, &ct);

	if (strcasecmp(ct.type, "MULTIPART") == 0) {
		if (!ct.has_boundary)
			return (-1);
		if (split_multipart(body, bodylen, ct.boundary, part_starts,
		    part_ends, &n, MIME_MAX_PARTS) == -1)
			return (-1);

		if (envbuf_append(out, outsize, outlen, "(", 1) == -1)
			return (-1);
		for (i = 0; i < n; i++) {
			pbuf = body + part_starts[i];
			plen = part_ends[i] - part_starts[i];

			/* An empty part is legal. */
			if (plen == 0)
				phdrend = 0;
			else if (find_header_body_split(pbuf, plen,
			    &phdrend) == -1)
				return (-1);
			if (build_part_structure(depth + 1, nparts_used, pbuf,
			    phdrend, pbuf + phdrend, plen - phdrend, out,
			    outsize, outlen) == -1)
				return (-1);
		}
		if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
			return (-1);
		if (envbuf_append_nstring(out, outsize, outlen, ct.subtype,
		    strlen(ct.subtype)) == -1)
			return (-1);
		return (envbuf_append(out, outsize, outlen, ")", 1));
	}

	is_text = strcasecmp(ct.type, "TEXT") == 0;
	is_msg = strcasecmp(ct.type, "MESSAGE") == 0 &&
	    (strcasecmp(ct.subtype, "RFC822") == 0 ||
	    strcasecmp(ct.subtype, "GLOBAL") == 0);

	if (envbuf_append(out, outsize, outlen, "(", 1) == -1)
		return (-1);
	if (envbuf_append_nstring(out, outsize, outlen, ct.type,
	    strlen(ct.type)) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);
	if (envbuf_append_nstring(out, outsize, outlen, ct.subtype,
	    strlen(ct.subtype)) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);
	if (content_type_params(hdr, hdrlen, out, outsize, outlen) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	if (extract_header_field(hdr, hdrlen, "Content-Id", &idval,
	    &idlen) == 0)
		rc = envbuf_append_nstring(out, outsize, outlen, idval, idlen);
	else
		rc = envbuf_append_nstring(out, outsize, outlen, NULL, 0);
	free(idval);
	if (rc == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	if (extract_header_field(hdr, hdrlen, "Content-Description",
	    &descval, &desclen) == 0)
		rc = envbuf_append_nstring(out, outsize, outlen, descval,
		    desclen);
	else
		rc = envbuf_append_nstring(out, outsize, outlen, NULL, 0);
	free(descval);
	if (rc == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	if (extract_header_field(hdr, hdrlen, "Content-Transfer-Encoding",
	    &encval, &enclen) == 0 && enclen > 0 && enclen < sizeof(encstr)) {
		memcpy(encstr, encval, enclen);
		encstr[enclen] = '\0';
	} else
		strlcpy(encstr, "7BIT", sizeof(encstr));
	free(encval);
	enc = encstr;
	for (j = 0; j < nitems(cte_known); j++) {
		if (strcasecmp(encstr, cte_known[j]) == 0) {
			enc = cte_known[j];
			break;
		}
	}
	if (envbuf_append_nstring(out, outsize, outlen, enc, strlen(enc)) == -1)
		return (-1);
	if (envbuf_append(out, outsize, outlen, " ", 1) == -1)
		return (-1);

	snprintf(numbuf, sizeof(numbuf), "%zu", bodylen);
	if (envbuf_append_str(out, outsize, outlen, numbuf) == -1)
		return (-1);

	/* A message/rfc822 part adds envelope, body and lines. */
	if (is_msg && (bodylen == 0 ||
	    find_header_body_split(body, bodylen, &ihdr) == -1 ||
	    envbuf_append(out, outsize, outlen, " ", 1) == -1 ||
	    envelope_from_header(body, ihdr, out, outsize, outlen) == -1 ||
	    envbuf_append(out, outsize, outlen, " ", 1) == -1 ||
	    build_part_structure(depth + 1, nparts_used, body, ihdr,
	    body + ihdr, bodylen - ihdr, out, outsize, outlen) == -1))
		return (-1);

	if (is_text || is_msg) {
		lines = 0;

		for (j = 0; j < bodylen; j++) {
			if (body[j] == '\n')
				lines++;
		}
		snprintf(numbuf, sizeof(numbuf), " %zu", lines);
		if (envbuf_append_str(out, outsize, outlen, numbuf) == -1)
			return (-1);
	}

	return (envbuf_append(out, outsize, outlen, ")", 1));
}

int
build_bodystructure(int fd, const char *basename, char **buf_out,
    uint32_t *len_out)
{
	uint32_t	 wholelen = 0;
	size_t		 hdrend;
	size_t		 outlen = 0;
	char		*wholebuf = NULL;
	char		 out[BODYSTRUCTURE_MAX];
	int		 nparts_used = 0;

	*buf_out = NULL;
	*len_out = 0;

	if (read_body_from_fd(fd, basename, 0, bodystructure_read_max,
	    "BODYSTRUCTURE", &wholebuf, &wholelen) == -1)
		return (-1);
	if (wholelen == 0 ||
	    find_header_body_split(wholebuf, wholelen, &hdrend) == -1) {
		free(wholebuf);
		return (-1);
	}

	if (build_part_structure(0, &nparts_used, wholebuf, hdrend,
	    wholebuf + hdrend, wholelen - hdrend, out, sizeof(out),
	    &outlen) == -1) {
		free(wholebuf);
		return (-1);
	}
	free(wholebuf);

	if ((*buf_out = malloc(outlen)) == NULL) {
		log_warn("malloc BODYSTRUCTURE buffer (%s)", basename);
		return (-1);
	}
	memcpy(*buf_out, out, outlen);
	*len_out = (uint32_t)outlen;
	return (0);
}
