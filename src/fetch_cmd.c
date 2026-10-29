#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"

struct fetch_atts {
	uint32_t	 attrs;
	int		 degraded;
	int		 bodystructure_full;
	int		 header_fields_not;
	int		 has_partial;
	uint32_t	 partial_start;
	uint32_t	 partial_count;
	char		 header_fields[HEADER_FIELDS_MAX];
	char		 header_fields_label[HEADER_FIELDS_LABEL_MAX];
	char		 section_part[SECTION_PART_MAX];
};

static int		 parse_one_seq_range(const char *, struct seq_range *);
static char		*fetch_att_tok(char *, char **);
static int		 parse_header_fields_att(const char *, int *, char *,
		    size_t);
static int		 section_part_valid(const char *);
static int		 parse_partial_suffix(const char *, int *, uint32_t *,
		    uint32_t *);
static int		 parse_body_peek_section_tok(const char *,
		    struct fetch_atts *, int *, const char **);
static int		 parse_body_peek_header_fields_tok(const char *,
		    struct fetch_atts *, const char **);
static const char	*body_section(const char *, int *);
static int		 parse_fetch_atts(char *, struct fetch_atts *,
		    const char **);
static void		 format_internaldate(int64_t, char *, size_t);
static void		 session_write_file_range(struct session *, int,
		    uint64_t, uint64_t);
static int		 parse_fetch_modifiers(char *, struct imsg_mbox_fetch *,
		    const struct session *, int, int *, const char **);
static int		 fetch_unliteral(char *, char *, size_t, const char **);

/*
 * An nz-number has no sign or leading zero.
 */
int
parse_nz_number(const char *str, uint32_t *out)
{
	const char	*errstr;
	long long	 v;

	if (str == NULL || *str < '1' || *str > '9')
		return (-1);

	v = strtonum(str, 1, UINT32_MAX, &errstr);
	if (errstr != NULL)
		return (-1);

	*out = (uint32_t)v;
	return (0);
}

static int
parse_one_seq_range(const char *tok, struct seq_range *r)
{
	const char	*loside, *hiside;
	uint32_t	 tmp;
	char		 buf[32];
	char		*colon;

	if (tok == NULL || *tok == '\0' || strlen(tok) >= sizeof(buf))
		return (-1);
	if (strlcpy(buf, tok, sizeof(buf)) >= sizeof(buf))
		return (-1);

	r->lo_is_star = r->hi_is_star = 0;
	r->lo = r->hi = 0;

	if ((colon = strchr(buf, ':')) != NULL) {
		*colon = '\0';
		loside = buf;
		hiside = colon + 1;
	} else {
		loside = buf;
		hiside = buf;
	}

	if (strcmp(loside, "*") == 0)
		r->lo_is_star = 1;
	else if (parse_nz_number(loside, &r->lo) == -1)
		return (-1);

	if (strcmp(hiside, "*") == 0)
		r->hi_is_star = 1;
	else if (parse_nz_number(hiside, &r->hi) == -1)
		return (-1);

	if (!r->lo_is_star && !r->hi_is_star && r->lo > r->hi) {
		tmp = r->lo;

		r->lo = r->hi;
		r->hi = tmp;
	}

	return (0);
}

/*
 * RFC 9051 section 9 sequence-set.
 */
int
parse_sequence_set(const char *text, struct seq_range ranges[SEQSET_MAX_RANGES],
    uint32_t *nranges, const char **errmsg)
{
	const char	*p, *start;
	uint32_t	 n = 0;
	size_t		 len;
	char		 tok[32];

	if (text == NULL || *text == '\0') {
		*errmsg = "empty sequence set";
		return (-1);
	}

	for (p = text; ; ) {
		start = p;

		while (*p != '\0' && *p != ',')
			p++;
		len = (size_t)(p - start);
		if (len == 0 || len >= sizeof(tok)) {
			*errmsg = "invalid sequence set";
			return (-1);
		}
		if (n >= SEQSET_MAX_RANGES) {
			*errmsg = "sequence set has too many comma-separated "
			    "ranges";
			return (-1);
		}
		memcpy(tok, start, len);
		tok[len] = '\0';

		if (strcmp(tok, "$") == 0 && *p == '\0') {
			memset(&ranges[n++], 0, sizeof(ranges[0]));
			break;
		}
		if (parse_one_seq_range(tok, &ranges[n]) == -1) {
			*errmsg = "invalid sequence set";
			return (-1);
		}
		n++;

		if (*p == '\0')
			break;
		p++;
	}

	*nranges = n;
	return (0);
}

/*
 * Like strsep(3), but bracketed, parenthesised or quoted spaces stay.
 */
static char *
fetch_att_tok(char *str, char **savep)
{
	char	*p, *start;
	int	 depth = 0;

	p = (str != NULL) ? str : *savep;
	if (p == NULL)
		return (NULL);

	for (start = p; *p != '\0'; p++) {
		if (*p == '"') {
			while (*++p != '\0' && *p != '"')
				if (*p == '\\' && p[1] != '\0')
					p++;
			if (*p == '\0')
				break;
		} else if (*p == '[' || *p == '(')
			depth++;
		else if (*p == ']' || *p == ')') {
			if (depth > 0)
				depth--;
		} else if (*p == ' ' && depth == 0)
			break;
	}

	if (*p != '\0') {
		*p = '\0';
		*savep = p + 1;
	} else
		*savep = NULL;
	return (start);
}

static int
parse_header_fields_att(const char *inner, int *not_out, char *fields_out,
    size_t fields_outsize)
{
	const char	*p = inner, *errmsg;
	size_t		 n, used;
	char		 name[HEADER_FIELDS_MAX];
	int		 first = 1;

	*not_out = 0;
	fields_out[0] = '\0';

	if (strlen(inner) >= HEADER_FIELDS_LABEL_MAX)
		return (-1);
	if (strncasecmp(p, "HEADER.FIELDS", 13) != 0)
		return (-1);
	p += 13;
	if (strncasecmp(p, ".NOT", 4) == 0) {
		*not_out = 1;
		p += 4;
	}
	if (p[0] != ' ' || p[1] != '(')
		return (-1);
	p += 2;

	for (;;) {
		n = 0;
		if (*p == '"') {
			if (read_quoted(p, name, sizeof(name), &n, &used,
			    &errmsg) == -1 || n >= sizeof(name))
				return (-1);
			p += used;
		} else {
			for (; *p != '\0' && *p != ' ' && *p != ')'; p++) {
				if (*p == '"' || n + 1 >= sizeof(name))
					return (-1);
				name[n++] = *p;
			}
		}
		name[n] = '\0';
		/* The store takes the names separated by spaces. */
		if (n == 0 || strchr(name, ' ') != NULL)
			return (-1);
		if (!first &&
		    strlcat(fields_out, " ", fields_outsize) >= fields_outsize)
			return (-1);
		if (strlcat(fields_out, name, fields_outsize) >= fields_outsize)
			return (-1);
		first = 0;
		if (*p != ' ')
			break;
		p++;
	}
	if (*p != ')' || p[1] != '\0')
		return (-1);
	return (0);
}

/*
 * RFC 9051 section 6.4.5.1 section-part.
 */
static int
section_part_valid(const char *s)
{
	int	 n = 0;

	if (s == NULL || *s == '\0')
		return (0);

	while (*s != '\0') {
		if (*s < '1' || *s > '9')	/* No leading zero. */
			return (0);
		if (n >= MIME_MAX_DEPTH)
			return (0);
		n++;
		while (*s >= '0' && *s <= '9')
			s++;
		if (*s == '\0')
			return (1);
		if (*s != '.')
			return (0);
		s++;
		if (*s == '\0')
			return (0);
	}
	return (1);
}

static int
parse_partial_suffix(const char *s, int *has_partial_out,
    uint32_t *start_out, uint32_t *count_out)
{
	unsigned long	 start, count;
	const char	*p;
	char		*end;

	*has_partial_out = 0;
	*start_out = 0;
	*count_out = 0;

	if (s == NULL || *s == '\0')
		return (0);

	if (s[0] != '<')
		return (-1);
	p = s + 1;

	if (*p < '0' || *p > '9')
		return (-1);
	errno = 0;
	start = strtoul(p, &end, 10);
	if (errno != 0 || start > UINT32_MAX || *end != '.')
		return (-1);
	p = end + 1;

	if (*p < '0' || *p > '9')
		return (-1);
	errno = 0;
	count = strtoul(p, &end, 10);
	if (errno != 0 || count > UINT32_MAX || *end != '>' || end[1] != '\0')
		return (-1);

	*has_partial_out = 1;
	*start_out = (uint32_t)start;
	*count_out = (uint32_t)count;
	return (0);
}

static int
parse_body_peek_section_tok(const char *bracket_start, struct fetch_atts *fa,
    int *degraded_out, const char **errmsg)
{
	const char	*suffix;
	char		*close;
	char		 inner[SECTION_PART_MAX];

	close = strchr(bracket_start, ']');
	if (close == NULL) {
		*degraded_out = 1;
		return (0);
	}
	if ((size_t)(close - bracket_start) >= sizeof(inner)) {
		*degraded_out = 1;
		return (0);
	}
	memcpy(inner, bracket_start, close - bracket_start);
	inner[close - bracket_start] = '\0';
	suffix = close + 1;

	if (suffix[0] != '\0' &&
	    parse_partial_suffix(suffix, &fa->has_partial, &fa->partial_start,
	    &fa->partial_count) == -1) {
		*errmsg = "malformed <partial> range";
		return (-1);
	}

	if (inner[0] == '\0') {
		fa->attrs |= MBOX_FETCH_BODY_WHOLE;
	} else if (strcasecmp(inner, "TEXT") == 0) {
		fa->attrs |= MBOX_FETCH_BODY_TEXT;
	} else if (section_part_valid(inner)) {
		fa->attrs |= MBOX_FETCH_BODY_PART;
		if (strlcpy(fa->section_part, inner,
		    sizeof(fa->section_part)) >= sizeof(fa->section_part)) {
			fa->attrs &= ~MBOX_FETCH_BODY_PART;
			*degraded_out = 1;
			return (0);
		}
	} else {
		/* Any other section, such as 2.1.TEXT, is unsupported. */
		*degraded_out = 1;
		return (0);
	}

	return (1);
}

static int
parse_body_peek_header_fields_tok(const char *sec, struct fetch_atts *fa,
    const char **errmsg)
{
	size_t	 len;
	char	 inner[HEADER_FIELDS_LABEL_MAX];

	len = strlen(sec);
	if (len < 1 || sec[len - 1] != ']') {
		*errmsg = "malformed HEADER.FIELDS section";
		return (-1);
	}
	if (fa->attrs & MBOX_FETCH_HEADER_FIELDS)
		return (0);

	if (len - 1 >= sizeof(inner)) {
		*errmsg = "HEADER.FIELDS section too long";
		return (-1);
	}
	memcpy(inner, sec, len - 1);
	inner[len - 1] = '\0';

	if (parse_header_fields_att(inner, &fa->header_fields_not,
	    fa->header_fields, sizeof(fa->header_fields)) == -1) {
		*errmsg = "malformed HEADER.FIELDS section";
		return (-1);
	}
	if (strlcpy(fa->header_fields_label, inner,
	    sizeof(fa->header_fields_label)) >=
	    sizeof(fa->header_fields_label)) {
		*errmsg = "HEADER.FIELDS section too long";
		return (-1);
	}
	fa->attrs |= MBOX_FETCH_HEADER_FIELDS;
	return (1);
}

static const char *
body_section(const char *tok, int *plain)
{
	*plain = strncasecmp(tok, "BODY[", 5) == 0;
	if (*plain)
		return (tok + 5);
	if (strncasecmp(tok, "BODY.PEEK[", 10) == 0)
		return (tok + 10);
	return (NULL);
}

/*
 * Unsupported items are skipped, and the command completes NO.
 */
static int
parse_fetch_atts(char *spec, struct fetch_atts *fa, const char **errmsg)
{
	const char	*sec;
	size_t		 len;
	char		*p, *tok, *save;
	int		 plain, d;

	memset(fa, 0, sizeof(*fa));

	if (spec == NULL || *spec == '\0') {
		*errmsg = "missing message data item(s)";
		return (-1);
	}

	p = spec;
	len = strlen(p);
	if (len >= 2 && p[0] == '(' && p[len - 1] == ')') {
		p[len - 1] = '\0';
		p++;
	}
	if (*p == '\0') {
		*errmsg = "empty message data item list";
		return (-1);
	}

	for (tok = fetch_att_tok(p, &save); tok != NULL;
	    tok = fetch_att_tok(NULL, &save)) {
		if (*tok == '\0') {
			*errmsg = "extra space";
			return (-1);
		}
		if (strcasecmp(tok, "FAST") == 0) {
			fa->attrs |= MBOX_FETCH_FLAGS |
			    MBOX_FETCH_INTERNALDATE | MBOX_FETCH_RFC822_SIZE;
		} else if (strcasecmp(tok, "ALL") == 0) {
			fa->attrs |= MBOX_FETCH_FLAGS |
			    MBOX_FETCH_INTERNALDATE | MBOX_FETCH_RFC822_SIZE |
			    MBOX_FETCH_ENVELOPE;
		} else if (strcasecmp(tok, "FULL") == 0) {
			fa->attrs |= MBOX_FETCH_FLAGS |
			    MBOX_FETCH_INTERNALDATE | MBOX_FETCH_RFC822_SIZE |
			    MBOX_FETCH_ENVELOPE | MBOX_FETCH_BODYSTRUCTURE;
		} else if (strcasecmp(tok, "FLAGS") == 0) {
			fa->attrs |= MBOX_FETCH_FLAGS;
		} else if (strcasecmp(tok, "UID") == 0) {
			fa->attrs |= MBOX_FETCH_UID;
		} else if (strcasecmp(tok, "INTERNALDATE") == 0) {
			fa->attrs |= MBOX_FETCH_INTERNALDATE;
		} else if (strcasecmp(tok, "RFC822.SIZE") == 0) {
			fa->attrs |= MBOX_FETCH_RFC822_SIZE;
		} else if (strcasecmp(tok, "MODSEQ") == 0) {
			fa->attrs |= MBOX_FETCH_MODSEQ;
		} else if ((sec = body_section(tok, &plain)) != NULL) {
			d = 0;
			if (strcasecmp(sec, "HEADER]") == 0)
				fa->attrs |= MBOX_FETCH_BODY_HEADER;
			else if (strncasecmp(sec, "HEADER.FIELDS",
			    strlen("HEADER.FIELDS")) == 0) {
				if (parse_body_peek_header_fields_tok(sec, fa,
				    errmsg) == -1)
					return (-1);
			} else if (parse_body_peek_section_tok(sec, fa, &d,
			    errmsg) == -1)
				return (-1);
			if (plain && !d)
				fa->attrs |= MBOX_FETCH_SET_SEEN;
			fa->degraded |= d;
		} else if (strcasecmp(tok, "ENVELOPE") == 0) {
			fa->attrs |= MBOX_FETCH_ENVELOPE;
		} else if (strcasecmp(tok, "BODY") == 0 ||
		    strcasecmp(tok, "BODYSTRUCTURE") == 0) {
			fa->attrs |= MBOX_FETCH_BODYSTRUCTURE;
			fa->bodystructure_full =
			    (strcasecmp(tok, "BODYSTRUCTURE") == 0);
		} else if (strncasecmp(tok, "BODY", 4) == 0 ||
		    strcasecmp(tok, "RFC822") == 0 ||
		    strcasecmp(tok, "RFC822.HEADER") == 0 ||
		    strcasecmp(tok, "RFC822.TEXT") == 0) {
			/* Known, but not implemented. */
			fa->degraded = 1;
		} else {
			*errmsg = "unknown message data item";
			return (-1);
		}
	}

	if (fa->attrs == 0) {
		*errmsg = "cannot fetch that message content yet, "
		    "supported: FLAGS/UID/INTERNALDATE/RFC822.SIZE/MODSEQ/"
		    "ENVELOPE/(BODY|BODYSTRUCTURE)/BODY[...]/BODY.PEEK[...]";
		return (PARSE_NO);
	}

	/* Only one header item fits, and HEADER holds all. */
	if ((fa->attrs & MBOX_FETCH_BODY_HEADER) &&
	    (fa->attrs & MBOX_FETCH_HEADER_FIELDS))
		fa->attrs &= ~MBOX_FETCH_HEADER_FIELDS;

	return (0);
}

const char *fetch_month_names[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * RFC 9051 section 9 date-time.  UTC only, as the chroot lacks time zone
 * files.
 */
static void
format_internaldate(int64_t ts, char *out, size_t outsize)
{
	struct tm	 tm;
	time_t		 t = (time_t)ts;

	if (gmtime_r(&t, &tm) == NULL)
		fatalx("%s: gmtime_r", __func__);

	snprintf(out, outsize, "%2d-%s-%04d %02d:%02d:%02d +0000",
	    tm.tm_mday, fetch_month_names[tm.tm_mon], tm.tm_year + 1900,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void
line_append(char *buf, size_t bufsize, size_t *len, const char *fmt, ...)
{
	va_list	 ap;
	int	 n;

	va_start(ap, fmt);
	n = vsnprintf(buf + *len, bufsize - *len, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= bufsize - *len)
		fatalx("%s: response line overflow", __func__);
	*len += (size_t)n;
}

/*
 * Short reads are fatal, since the length was sent.
 */
static void
session_write_file_range(struct session *s, int fd, uint64_t off,
    uint64_t len)
{
	ssize_t	n;
	size_t	want;
	char	buf[16384];

	while (len > 0 && !s->write_failed) {
		want = len < sizeof(buf) ? (size_t)len : sizeof(buf);
		if ((n = pread(fd, buf, want, (off_t)off)) == -1 &&
		    errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == -1)
				log_warn("session %u: read FETCH body", s->id);
			else
				log_warnx("session %u: FETCH body ended %llu "
				    "octets early", s->id,
				    (unsigned long long)len);
			s->write_failed = 1;
			(void)shutdown(s->client_fd, SHUT_RDWR);
			return;
		}
		session_write(s, buf, (size_t)n);
		off += (uint64_t)n;
		len -= (uint64_t)n;
	}
}

void
session_send_fetch_response(struct session *s,
    struct imsg_mbox_fetch_meta *meta)
{
	struct session_cmd	*c = &s->cmd;
	char			 buf[768];
	char			 date[40];
	size_t			 len = 0;
	int			 need_sp = 0;
	int			 cs = meta->seen_set && s->condstore_enabled;
	int			 have_header =
	    (c->fetch_attrs & (MBOX_FETCH_BODY_HEADER |
	    MBOX_FETCH_HEADER_FIELDS)) && c->pending_header_found;
	int			 have_body = (c->fetch_attrs &
	    (MBOX_FETCH_BODY_WHOLE | MBOX_FETCH_BODY_TEXT |
	    MBOX_FETCH_BODY_PART)) && c->pending_body_found;
	int			 have_envelope =
	    (c->fetch_attrs & MBOX_FETCH_ENVELOPE) && c->pending_envelope_found;
	int			 have_bodystructure =
	    (c->fetch_attrs & MBOX_FETCH_BODYSTRUCTURE) &&
	    c->pending_bodystructure_found;

	line_append(buf, sizeof(buf), &len, "%u FETCH (", meta->seqno);

	/*
	 * An implicit \Seen sends FLAGS.  Under CONDSTORE it also sends UID
	 * and MODSEQ.
	 */
	if ((c->fetch_attrs & MBOX_FETCH_FLAGS) || meta->seen_set) {
		line_append(buf, sizeof(buf), &len, "FLAGS (%s)", meta->flags);
		need_sp = 1;
	}
	if ((c->fetch_attrs & MBOX_FETCH_UID) || cs) {
		line_append(buf, sizeof(buf), &len, "%sUID %u",
		    need_sp ? " " : "", meta->uid);
		need_sp = 1;
	}
	if (c->fetch_attrs & MBOX_FETCH_INTERNALDATE) {
		format_internaldate(meta->internaldate, date, sizeof(date));
		line_append(buf, sizeof(buf), &len, "%sINTERNALDATE \"%s\"",
		    need_sp ? " " : "", date);
		need_sp = 1;
	}
	if (c->fetch_attrs & MBOX_FETCH_RFC822_SIZE) {
		line_append(buf, sizeof(buf), &len, "%sRFC822.SIZE %llu",
		    need_sp ? " " : "", (unsigned long long)meta->size);
		need_sp = 1;
	}
	if ((c->fetch_attrs & MBOX_FETCH_MODSEQ) || cs) {
		line_append(buf, sizeof(buf), &len, "%sMODSEQ (%llu)",
		    need_sp ? " " : "", (unsigned long long)meta->modseq);
		need_sp = 1;
	}

	if (have_header || have_body || have_envelope || have_bodystructure) {
		session_write(s, "* ", 2);
		session_write(s, buf, len);

		if (have_envelope) {
			len = 0;
			line_append(buf, sizeof(buf), &len, "%sENVELOPE ",
			    need_sp ? " " : "");
			session_write(s, buf, len);
			if (c->pending_envelope_len > 0)
				session_write(s, c->pending_envelope_buf,
				    c->pending_envelope_len);
			need_sp = 1;
		}
		if (have_bodystructure) {
			len = 0;
			line_append(buf, sizeof(buf), &len, "%s%s ",
			    need_sp ? " " : "", c->pending_bodystructure_label);
			session_write(s, buf, len);
			if (c->pending_bodystructure_len > 0)
				session_write(s, c->pending_bodystructure_buf,
				    c->pending_bodystructure_len);
			need_sp = 1;
		}
		if (have_header) {
			len = 0;
			line_append(buf, sizeof(buf), &len,
			    "%sBODY[%s] {%u}\r\n", need_sp ? " " : "",
			    c->pending_header_label, c->pending_header_len);
			session_write(s, buf, len);
			if (c->pending_header_len > 0)
				session_write(s, c->pending_header_buf,
				    c->pending_header_len);
			need_sp = 1;
		}
		if (have_body) {
			len = 0;
			if (c->pending_body_has_partial)
				line_append(buf, sizeof(buf), &len,
				    "%sBODY[%s]<%u> {%llu}\r\n",
				    need_sp ? " " : "", c->pending_body_label,
				    c->pending_body_partial_origin,
				    (unsigned long long)c->pending_body_len);
			else
				line_append(buf, sizeof(buf), &len,
				    "%sBODY[%s] {%llu}\r\n", need_sp ? " " : "",
				    c->pending_body_label,
				    (unsigned long long)c->pending_body_len);
			session_write(s, buf, len);
			if (c->pending_body_len > 0)
				session_write_file_range(s, c->pending_body_fd,
				    c->pending_body_off, c->pending_body_len);
		}
		session_write(s, ")\r\n", 3);
	} else {
		line_append(buf, sizeof(buf), &len, ")");
		session_untagged(s, buf);
	}

	if (have_header) {
		free(c->pending_header_buf);
		c->pending_header_buf = NULL;
		c->pending_header_len = 0;
	}
	if (c->fetch_attrs &
	    (MBOX_FETCH_BODY_HEADER | MBOX_FETCH_HEADER_FIELDS)) {
		if (!have_header)
			c->fetch_incomplete = 1;
		c->pending_header_found = 0;
	}

	if (have_body) {
		if (c->pending_body_fd != -1)
			close(c->pending_body_fd);
		c->pending_body_fd = -1;
		c->pending_body_off = 0;
		c->pending_body_len = 0;
	}
	if (c->fetch_attrs & (MBOX_FETCH_BODY_WHOLE | MBOX_FETCH_BODY_TEXT |
	    MBOX_FETCH_BODY_PART)) {
		if (!have_body)
			c->fetch_incomplete = 1;
		c->pending_body_found = 0;
	}

	if (have_envelope) {
		free(c->pending_envelope_buf);
		c->pending_envelope_buf = NULL;
		c->pending_envelope_len = 0;
	}
	if (c->fetch_attrs & MBOX_FETCH_ENVELOPE) {
		if (!have_envelope)
			c->fetch_incomplete = 1;
		c->pending_envelope_found = 0;
	}

	if (have_bodystructure) {
		free(c->pending_bodystructure_buf);
		c->pending_bodystructure_buf = NULL;
		c->pending_bodystructure_len = 0;
	}
	if (c->fetch_attrs & MBOX_FETCH_BODYSTRUCTURE) {
		if (!have_bodystructure)
			c->fetch_incomplete = 1;
		c->pending_bodystructure_found = 0;
	}
}

void
session_send_store_fetch_response(struct session *s,
    const struct imsg_mbox_fetch_meta *meta)
{
	size_t	len = 0;
	char	buf[MBOX_FLAGS_MAX + 96];

	line_append(buf, sizeof(buf), &len, "%u FETCH (FLAGS (%s)",
	    meta->seqno, meta->flags);
	if (s->cmd.cmd_by_uid)
		line_append(buf, sizeof(buf), &len, " UID %u", meta->uid);
	if (s->condstore_enabled)
		line_append(buf, sizeof(buf), &len, " MODSEQ (%llu)",
		    (unsigned long long)meta->modseq);
	line_append(buf, sizeof(buf), &len, ")");

	session_untagged(s, buf);
}

static int
parse_fetch_modifiers(char *modspec, struct imsg_mbox_fetch *req,
    const struct session *s, int by_uid, int *want_vanished,
    const char **errmsg)
{
	const char	*valtok, *errstr;
	size_t		 len;
	char		*p, *tok;

	*want_vanished = 0;
	len = strlen(modspec);
	if (len < 2 || modspec[0] != '(' || modspec[len - 1] != ')') {
		*errmsg = "malformed fetch-modifier list";
		return (-1);
	}
	modspec[len - 1] = '\0';
	p = modspec + 1;
	if (*p == '\0') {
		*errmsg = "empty fetch-modifier list";
		return (-1);
	}

	while ((tok = strsep(&p, " ")) != NULL) {
		if (*tok == '\0') {
			*errmsg = "extra space";
			return (-1);
		}
		if (strcasecmp(tok, "CHANGEDSINCE") == 0) {
			valtok = strsep(&p, " ");
			if (valtok == NULL) {
				*errmsg = "CHANGEDSINCE requires a "
				    "mod-sequence value";
				return (-1);
			}
			if (*valtok == '\0') {
				*errmsg = "extra space";
				return (-1);
			}
			if (*valtok < '0' || *valtok > '9') {
				*errmsg = "invalid CHANGEDSINCE mod-sequence";
				return (-1);
			}
			req->changedsince = strtonum(valtok, 1, MODSEQ_MAX,
			    &errstr);
			if (errstr != NULL) {
				*errmsg = "invalid CHANGEDSINCE mod-sequence";
				return (-1);
			}
			req->has_changedsince = 1;
			req->attrs |= MBOX_FETCH_MODSEQ;
		} else if (strcasecmp(tok, "VANISHED") == 0) {
			if (!by_uid) {
				*errmsg = "VANISHED is only valid as a UID "
				    "FETCH modifier";
				return (-1);
			}
			if (!s->qresync_enabled) {
				*errmsg = "VANISHED requires ENABLE QRESYNC "
				    "first";
				return (-1);
			}
			*want_vanished = 1;
		} else {
			*errmsg = "unrecognized fetch modifier";
			return (-1);
		}
	}

	return (0);
}

/*
 * Rewrite each literal as a quoted string.  In FETCH only a header field
 * name can be a literal.
 */
static int
fetch_unliteral(char *spec, char *out, size_t outsize, const char **errmsg)
{
	size_t	 o = 0, len, i;
	char	*p = spec, *lit;
	int	 inquote = 0;

	while (*p != '\0') {
		if (!inquote && *p == '{') {
			if (read_literal(&p, &lit, &len, errmsg) == -1)
				return (-1);
			if (o + 2 * len + 2 >= outsize) {
				*errmsg = "FETCH arguments too long";
				return (-1);
			}
			out[o++] = '"';
			for (i = 0; i < len; i++) {
				if (lit[i] == '\r' || lit[i] == '\n') {
					*errmsg = "CR or LF in a field name";
					return (-1);
				}
				if (lit[i] == '"' || lit[i] == '\\')
					out[o++] = '\\';
				out[o++] = lit[i];
			}
			out[o++] = '"';
			continue;
		}
		if (o + 2 >= outsize) {
			*errmsg = "FETCH arguments too long";
			return (-1);
		}
		if (inquote && *p == '\\' && p[1] != '\0')
			out[o++] = *p++;
		else if (*p == '"')
			inquote = !inquote;
		out[o++] = *p++;
	}
	out[o] = '\0';
	return (0);
}

void
cmd_fetch(struct session *s, const char *tag, char *args)
{
	fetch_dispatch(s, tag, args, 0);
}

void
fetch_dispatch(struct session *s, const char *tag, char *args, int by_uid)
{
	struct imsg_mbox_fetch	 req;
	struct fetch_atts	 fa;
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	const char		*errmsg;
	const char		*cmdname = by_uid ? "UID FETCH" : "FETCH";
	uint32_t		 nranges;
	char			*seqtok, *attspec, *modspec;
	char			 unlit[SESSION_INBUF_MAX];
	int			 rc, want_vanished = 0;

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "FETCH requires a sequence set and message data item(s)");
		return;
	}

	if (next_word(&args, &seqtok, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (*args == '\0') {
		session_reply(s, tag, "BAD",
		    "FETCH requires message data item(s)");
		return;
	}
	attspec = args;

	if (parse_sequence_set(seqtok, ranges, &nranges, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (fetch_unliteral(attspec, unlit, sizeof(unlit), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	attspec = unlit;

	fetch_att_tok(attspec, &modspec);
	if (modspec != NULL && (*modspec == ' ' || *modspec == '\0')) {
		session_reply(s, tag, "BAD", "extra space");
		return;
	}

	rc = parse_fetch_atts(attspec, &fa, &errmsg);
	if (rc == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (rc == PARSE_NO) {
		session_reply(s, tag, "NO", errmsg);
		return;
	}
	/* EXAMINE permits no change, \Seen included. */
	if (s->mbox_readonly)
		fa.attrs &= ~MBOX_FETCH_SET_SEEN;
	if (fa.degraded)
		log_debug("session %u: %s: unsupported item skipped", s->id,
		    cmdname);

	memset(&req, 0, sizeof(req));
	req.attrs = fa.attrs;
	req.by_uid = by_uid;
	req.header_fields_not = fa.header_fields_not;
	req.has_partial = fa.has_partial;
	req.partial_start = fa.partial_start;
	req.partial_count = fa.partial_count;
	strlcpy(req.header_fields, fa.header_fields, sizeof(req.header_fields));
	strlcpy(req.section_part, fa.section_part, sizeof(req.section_part));

	if (fa.attrs & MBOX_FETCH_BODY_HEADER)
		strlcpy(s->cmd.pending_header_label, "HEADER",
		    sizeof(s->cmd.pending_header_label));
	else if (fa.attrs & MBOX_FETCH_HEADER_FIELDS)
		strlcpy(s->cmd.pending_header_label, fa.header_fields_label,
		    sizeof(s->cmd.pending_header_label));

	if (fa.attrs & MBOX_FETCH_BODY_WHOLE)
		s->cmd.pending_body_label[0] = '\0';
	else if (fa.attrs & MBOX_FETCH_BODY_TEXT)
		strlcpy(s->cmd.pending_body_label, "TEXT",
		    sizeof(s->cmd.pending_body_label));
	else if (fa.attrs & MBOX_FETCH_BODY_PART)
		strlcpy(s->cmd.pending_body_label, fa.section_part,
		    sizeof(s->cmd.pending_body_label));
	s->cmd.pending_body_has_partial = fa.has_partial;
	s->cmd.pending_body_partial_origin = fa.partial_start;

	if (fa.attrs & MBOX_FETCH_BODYSTRUCTURE)
		strlcpy(s->cmd.pending_bodystructure_label,
		    fa.bodystructure_full ? "BODYSTRUCTURE" : "BODY",
		    sizeof(s->cmd.pending_bodystructure_label));

	if (modspec != NULL) {
		if (parse_fetch_modifiers(modspec, &req, s, by_uid,
		    &want_vanished, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (want_vanished && !req.has_changedsince) {
		session_reply(s, tag, "BAD",
		    "VANISHED requires CHANGEDSINCE");
		return;
	}
	req.want_vanished = want_vanished;

	if (by_uid)
		req.attrs |= MBOX_FETCH_UID;

	req.nranges = nranges;

	/* MODSEQ and CHANGEDSINCE both enable CONDSTORE. */
	if (req.attrs & MBOX_FETCH_MODSEQ)
		session_condstore_enable(s);

	s->cmd.fetch_attrs = req.attrs;
	s->cmd.cmd_by_uid = by_uid;
	s->cmd.fetch_incomplete = fa.degraded;
	s->state = SESSION_FETCHING;

	if (send_mbox_request(s, IMSG_MBOX_FETCH, "IMSG_MBOX_FETCH", &req,
	    sizeof(req), ranges, nranges, sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
		return;
	}

}
