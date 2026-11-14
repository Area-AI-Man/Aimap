#include <sys/param.h>
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

struct fetch_att_section {
	struct imsg_fetch_section	 rec;
	char				 fields_label[HEADER_FIELDS_LABEL_MAX];
};

struct fetch_atts {
	struct fetch_att_section	 sections[FETCH_SECTIONS_MAX];
	uint32_t			 attrs;
	uint32_t			 nsections;
	int				 degraded;
	int				 limit;
	int				 bodystructure_full;
};

static const char *const section_text_names[] = {
	"", "HEADER", "TEXT", "MIME"
};

static int		 parse_one_seq_range(const char *, struct seq_range *);
static char		*fetch_att_tok(char *, char **);
static int		 parse_header_fields_att(const char *, int *, char *,
		    size_t);
static int		 section_part_valid(const char *);
static int		 section_part_syntax(const char *, size_t);
static size_t		 section_part_len(const char *);
static int		 section_part_copy(const char *, size_t,
		    struct fetch_atts *, char *);
static int		 section_text_kind(const char *, const char *, size_t);
static int		 parse_partial_suffix(const char *, int *, uint64_t *,
		    uint64_t *);
static int		 fetch_section_add(struct fetch_atts *,
		    const struct imsg_fetch_section *, const char *);
static int		 parse_body_peek_section_tok(const char *,
		    struct fetch_atts *, int *, const char **);
static int		 parse_body_peek_header_fields_tok(const char *,
		    struct imsg_fetch_section *, char[HEADER_FIELDS_LABEL_MAX],
		    const char **);
static int		 parse_body_tok(const char *, struct fetch_atts *,
		    int *, const char **);
static const char	*body_section(const char *, int *);
static const char	*binary_section(const char *, uint32_t *, int *);
static int		 parse_binary_section_tok(const char *, uint32_t,
		    struct fetch_atts *, const char **);
static int		 parse_fetch_atts(char *, struct fetch_atts *,
		    const char **);
static void		 format_internaldate(int64_t, char *, size_t);
static void		 session_write_file_range(struct session *, int,
		    uint64_t, uint64_t);
static void		 session_send_fetch_body(struct session *,
		    const struct fetch_slot *, int);
static void		 fetch_slot_label(struct fetch_slot *,
		    const struct fetch_att_section *);
static void		 fetch_set_labels(struct session_cmd *,
		    const struct fetch_atts *);
static void		 session_send_fetch_sections(struct session *, int);
static void		 fetch_slots_done(struct session *);
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
section_part_syntax(const char *s, size_t len)
{
	size_t	 i = 0;

	while (i < len) {
		if (s[i] < '1' || s[i] > '9')
			return (0);
		while (++i < len && s[i] >= '0' && s[i] <= '9')
			;
		if (i == len)
			return (1);
		if (s[i] != '.')
			return (0);
		i++;
	}
	return (0);
}

static size_t
section_part_len(const char *s)
{
	size_t	 n = 0;

	while ((s[n] >= '0' && s[n] <= '9') ||
	    (s[n] == '.' && s[n + 1] >= '0' && s[n + 1] <= '9'))
		n++;
	return (n);
}

static int
section_part_copy(const char *s, size_t n, struct fetch_atts *fa, char *out)
{
	if (n >= SECTION_PART_MAX) {
		if (section_part_syntax(s, n))
			fa->limit = 1;
		return (-1);
	}
	memcpy(out, s, n);
	out[n] = '\0';
	if (!section_part_valid(out)) {
		if (section_part_syntax(out, n))
			fa->limit = 1;
		return (-1);
	}
	return (0);
}

static int
section_text_kind(const char *s, const char *close, size_t n)
{
	const char	*text = s + n;
	size_t		 i, len;

	if (text == close)
		return (SECTION_TEXT_NONE);
	if (n > 0 && *text++ != '.')
		return (-1);
	len = close - text;
	for (i = 1; i < nitems(section_text_names); i++) {
		if (strlen(section_text_names[i]) == len &&
		    strncasecmp(text, section_text_names[i], len) == 0)
			return ((int)i);
	}
	return (-1);
}

static int
parse_partial_suffix(const char *s, int *has_partial_out,
    uint64_t *start_out, uint64_t *count_out)
{
	const char	*p;
	long long	 start, count;
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
	start = strtoll(p, &end, 10);
	if (errno != 0 || *end != '.')
		return (-1);
	p = end + 1;

	if (*p < '0' || *p > '9')
		return (-1);
	errno = 0;
	count = strtoll(p, &end, 10);
	if (errno != 0 || count == 0 || *end != '>' || end[1] != '\0')
		return (-1);

	*has_partial_out = 1;
	*start_out = (uint64_t)start;
	*count_out = (uint64_t)count;
	return (0);
}

static int
fetch_section_add(struct fetch_atts *fa, const struct imsg_fetch_section *rec,
    const char *fields_label)
{
	struct fetch_att_section	*fs;

	if (fa->nsections >= FETCH_SECTIONS_MAX) {
		fa->limit = 1;
		return (0);
	}
	fs = &fa->sections[fa->nsections++];
	fs->rec = *rec;
	strlcpy(fs->fields_label, fields_label, sizeof(fs->fields_label));
	return (1);
}

static int
parse_body_peek_section_tok(const char *bracket_start, struct fetch_atts *fa,
    int *degraded_out, const char **errmsg)
{
	struct imsg_fetch_section	 rec;
	const char			*close;
	uint64_t			 start, count;
	size_t				 n;
	int				 kind, has_partial;

	close = strchr(bracket_start, ']');
	if (close == NULL) {
		*degraded_out = 1;
		return (0);
	}
	n = section_part_len(bracket_start);
	kind = section_text_kind(bracket_start, close, n);
	if (n == 0 && kind != SECTION_TEXT_NONE && kind != SECTION_TEXT_TEXT)
		kind = -1;
	if (n >= sizeof(rec.part) || (kind == -1 &&
	    (size_t)(close - bracket_start) >= sizeof(rec.part))) {
		if (kind != -1 && section_part_syntax(bracket_start, n))
			fa->limit = 1;
		*degraded_out = 1;
		return (0);
	}

	if (parse_partial_suffix(close + 1, &has_partial, &start,
	    &count) == -1) {
		*errmsg = "malformed <partial> range";
		return (-1);
	}

	if (kind == -1) {
		*degraded_out = 1;
		return (0);
	}
	memset(&rec, 0, sizeof(rec));
	if (n == 0) {
		rec.kind = kind == SECTION_TEXT_NONE ? FETCH_SECTION_WHOLE :
		    FETCH_SECTION_TEXT;
	} else {
		if (section_part_copy(bracket_start, n, fa, rec.part) == -1) {
			*degraded_out = 1;
			return (0);
		}
		rec.kind = FETCH_SECTION_PART;
		rec.section_text = kind;
	}
	rec.has_partial = has_partial;
	rec.partial_start = start;
	rec.partial_count = count;
	if (!fetch_section_add(fa, &rec, "")) {
		*degraded_out = 1;
		return (0);
	}
	return (1);
}

static int
parse_body_peek_header_fields_tok(const char *sec,
    struct imsg_fetch_section *rec, char label[HEADER_FIELDS_LABEL_MAX],
    const char **errmsg)
{
	const char	*close;
	size_t		 len;

	if ((close = strrchr(sec, ']')) == NULL) {
		*errmsg = "malformed HEADER.FIELDS section";
		return (-1);
	}
	len = close - sec;

	if (len >= HEADER_FIELDS_LABEL_MAX) {
		*errmsg = "HEADER.FIELDS section too long";
		return (-1);
	}
	memcpy(label, sec, len);
	label[len] = '\0';

	if (parse_partial_suffix(close + 1, &rec->has_partial,
	    &rec->partial_start, &rec->partial_count) == -1) {
		*errmsg = "malformed <partial> range";
		return (-1);
	}

	if (parse_header_fields_att(label, &rec->fields_not, rec->fields,
	    sizeof(rec->fields)) == -1) {
		*errmsg = "malformed HEADER.FIELDS section";
		return (-1);
	}
	rec->kind = FETCH_SECTION_HEADER_FIELDS;
	return (0);
}

static int
parse_body_tok(const char *sec, struct fetch_atts *fa, int *degraded_out,
    const char **errmsg)
{
	struct imsg_fetch_section	 rec;
	const char			*text;
	size_t				 n;
	char				 label[HEADER_FIELDS_LABEL_MAX];
	int				 fields;

	n = section_part_len(sec);
	text = sec + n;
	if (n > 0 && *text == '.')
		text++;
	fields = text > sec + n || n == 0;
	fields = fields && strncasecmp(text, "HEADER.FIELDS",
	    strlen("HEADER.FIELDS")) == 0;
	/* Filtered in the parser, n.HEADER.FIELDS is a buffer. */
	if (!fields && (n > 0 ||
	    strncasecmp(text, "HEADER]", strlen("HEADER]")) != 0))
		return (parse_body_peek_section_tok(sec, fa, degraded_out,
		    errmsg));

	memset(&rec, 0, sizeof(rec));
	if (n > 0 && section_part_copy(sec, n, fa, rec.part) == -1) {
		*degraded_out = 1;
		return (0);
	}
	if (fields) {
		if (parse_body_peek_header_fields_tok(text, &rec, label,
		    errmsg) == -1)
			return (-1);
	} else {
		if (parse_partial_suffix(text + strlen("HEADER]"),
		    &rec.has_partial, &rec.partial_start,
		    &rec.partial_count) == -1) {
			*errmsg = "malformed <partial> range";
			return (-1);
		}
		rec.kind = FETCH_SECTION_HEADER;
		label[0] = '\0';
	}
	if (!fetch_section_add(fa, &rec, label)) {
		*degraded_out = 1;
		return (0);
	}
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

static const char *
binary_section(const char *tok, uint32_t *kind, int *plain)
{
	*plain = strncasecmp(tok, "BINARY[", 7) == 0;
	if (*plain) {
		*kind = FETCH_SECTION_BINARY;
		return (tok + 7);
	}
	if (strncasecmp(tok, "BINARY.PEEK[", 12) == 0) {
		*kind = FETCH_SECTION_BINARY;
		return (tok + 12);
	}
	if (strncasecmp(tok, "BINARY.SIZE[", 12) == 0) {
		*kind = FETCH_SECTION_BINARY_SIZE;
		return (tok + 12);
	}
	return (NULL);
}

static int
parse_binary_section_tok(const char *sec, uint32_t kind, struct fetch_atts *fa,
    const char **errmsg)
{
	struct imsg_fetch_section	 rec;
	const char			*close;
	size_t				 len;

	if ((close = strchr(sec, ']')) == NULL) {
		*errmsg = "malformed BINARY section";
		return (-1);
	}
	len = (size_t)(close - sec);
	if (len > 0 && !section_part_syntax(sec, len)) {
		*errmsg = "malformed BINARY section";
		return (-1);
	}
	if (kind == FETCH_SECTION_BINARY_SIZE && close[1] != '\0') {
		*errmsg = "BINARY.SIZE takes no partial";
		return (-1);
	}
	memset(&rec, 0, sizeof(rec));
	if (parse_partial_suffix(close + 1, &rec.has_partial,
	    &rec.partial_start, &rec.partial_count) == -1) {
		*errmsg = "malformed <partial> range";
		return (-1);
	}

	if (len >= sizeof(rec.part)) {
		fa->limit = fa->degraded = 1;
		return (0);
	}
	memcpy(rec.part, sec, len);
	rec.part[len] = '\0';
	if (len > 0 && !section_part_valid(rec.part)) {
		fa->limit = fa->degraded = 1;
		return (0);
	}
	/* The whole message has no one transfer encoding. */
	if (len == 0) {
		fa->degraded = 1;
		return (0);
	}
	rec.kind = kind;
	if (!fetch_section_add(fa, &rec, "")) {
		fa->degraded = 1;
		return (0);
	}
	return (1);
}

/*
 * Unsupported items are skipped, and the command completes NO.
 */
static int
parse_fetch_atts(char *spec, struct fetch_atts *fa, const char **errmsg)
{
	const char	*sec;
	uint32_t	 kind;
	size_t		 len;
	char		*p, *tok, *save;
	int		 plain, d, rc;

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
		} else if ((sec = binary_section(tok, &kind, &plain)) != NULL) {
			if ((rc = parse_binary_section_tok(sec, kind, fa,
			    errmsg)) == -1)
				return (-1);
			if (plain && rc == 1)
				fa->attrs |= MBOX_FETCH_SET_SEEN;
		} else if ((sec = body_section(tok, &plain)) != NULL) {
			d = 0;
			if (parse_body_tok(sec, fa, &d, errmsg) == -1)
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

	if (fa->attrs == 0 && fa->nsections == 0 && fa->limit) {
		*errmsg = "[LIMIT] section part too deep or too long";
		return (PARSE_NO);
	}
	if (fa->attrs == 0 && fa->nsections == 0) {
		*errmsg = "cannot fetch that message content yet, "
		    "supported: FLAGS/UID/INTERNALDATE/RFC822.SIZE/MODSEQ/"
		    "ENVELOPE/(BODY|BODYSTRUCTURE)/BODY[...]/BODY.PEEK[...]"
		    "/BINARY[...]/BINARY.PEEK[...]/BINARY.SIZE[...]";
		return (PARSE_NO);
	}

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

static void
session_send_fetch_body(struct session *s, const struct fetch_slot *slot,
    int need_sp)
{
	const char	*item = "BODY";
	char		 buf[128];
	size_t		 len = 0;

	if (slot->kind == FETCH_SECTION_BINARY_SIZE) {
		line_append(buf, sizeof(buf), &len, "%sBINARY.SIZE[%s] %llu",
		    need_sp ? " " : "", slot->label,
		    (unsigned long long)slot->size);
		session_write(s, buf, len);
		return;
	}
	if (slot->kind == FETCH_SECTION_BINARY)
		item = "BINARY";
	line_append(buf, sizeof(buf), &len, "%s%s[%s]", need_sp ? " " : "",
	    item, slot->label);
	if (slot->has_partial)
		line_append(buf, sizeof(buf), &len, "<%llu>",
		    (unsigned long long)slot->partial_origin);
	line_append(buf, sizeof(buf), &len, " %s{%llu}\r\n",
	    slot->literal8 ? "~" : "", (unsigned long long)slot->len);
	session_write(s, buf, len);
	if (slot->len > 0)
		session_write_file_range(s, slot->fd, slot->off, slot->len);
}

static void
fetch_slot_label(struct fetch_slot *slot, const struct fetch_att_section *fs)
{
	const struct imsg_fetch_section	*rec = &fs->rec;
	size_t				 size = sizeof(slot->label);

	slot->label[0] = '\0';
	switch (rec->kind) {
	case FETCH_SECTION_HEADER:
		strlcpy(slot->label, "HEADER", size);
		break;
	case FETCH_SECTION_HEADER_FIELDS:
		if (rec->part[0] != '\0') {
			strlcpy(slot->label, rec->part, size);
			strlcat(slot->label, ".", size);
		}
		strlcat(slot->label, fs->fields_label, size);
		break;
	case FETCH_SECTION_TEXT:
		strlcpy(slot->label, "TEXT", size);
		break;
	case FETCH_SECTION_PART:
	case FETCH_SECTION_BINARY:
	case FETCH_SECTION_BINARY_SIZE:
		strlcpy(slot->label, rec->part, size);
		if (rec->section_text != SECTION_TEXT_NONE) {
			strlcat(slot->label, ".", size);
			strlcat(slot->label,
			    section_text_names[rec->section_text], size);
		}
		break;
	default:
		break;
	}
}

static void
fetch_set_labels(struct session_cmd *c, const struct fetch_atts *fa)
{
	struct fetch_slot	*slot;
	uint32_t		 i;

	c->fetch_nslots = fa->nsections;
	for (i = 0; i < fa->nsections; i++) {
		slot = &c->fetch_slots[i];
		slot->kind = fa->sections[i].rec.kind;
		slot->has_partial = fa->sections[i].rec.has_partial;
		slot->partial_origin = fa->sections[i].rec.partial_start;
		fetch_slot_label(slot, &fa->sections[i]);
	}

	if (fa->attrs & MBOX_FETCH_BODYSTRUCTURE)
		strlcpy(c->pending_bodystructure_label,
		    fa->bodystructure_full ? "BODYSTRUCTURE" : "BODY",
		    sizeof(c->pending_bodystructure_label));
}

static void
session_send_fetch_sections(struct session *s, int need_sp)
{
	struct session_cmd	*c = &s->cmd;
	struct fetch_slot	*slot;
	uint32_t		 i;
	size_t			 len;
	char			 buf[HEADER_LABEL_MAX + 64];

	for (i = 0; i < c->fetch_nslots; i++) {
		slot = &c->fetch_slots[i];
		if (!slot->found)
			continue;
		if (!FETCH_SECTION_IS_HEADER(slot->kind)) {
			session_send_fetch_body(s, slot, need_sp);
			need_sp = 1;
			continue;
		}
		len = 0;
		line_append(buf, sizeof(buf), &len, "%sBODY[%s]",
		    need_sp ? " " : "", slot->label);
		if (slot->has_partial)
			line_append(buf, sizeof(buf), &len, "<%llu>",
			    (unsigned long long)slot->partial_origin);
		line_append(buf, sizeof(buf), &len, " {%u}\r\n", slot->hdr_len);
		session_write(s, buf, len);
		if (slot->hdr_len > 0)
			session_write(s, slot->hdr_buf, slot->hdr_len);
		need_sp = 1;
	}
}

static void
fetch_slots_done(struct session *s)
{
	struct session_cmd	*c = &s->cmd;
	struct fetch_slot	*slot;
	uint32_t		 i;

	for (i = 0; i < c->fetch_nslots; i++) {
		slot = &c->fetch_slots[i];
		if (!slot->found)
			c->fetch_incomplete = 1;
		free(slot->hdr_buf);
		slot->hdr_buf = NULL;
		slot->hdr_len = 0;
		if (slot->fd != -1)
			close(slot->fd);
		slot->fd = -1;
		slot->off = 0;
		slot->len = 0;
		slot->size = 0;
		slot->literal8 = 0;
		slot->found = 0;
	}
}

void
session_send_fetch_response(struct session *s,
    struct imsg_mbox_fetch_meta *meta)
{
	struct session_cmd	*c = &s->cmd;
	char			 buf[768];
	char			 date[40];
	uint32_t		 i;
	size_t			 len = 0;
	int			 need_sp = 0;
	int			 cs = meta->seen_set && s->condstore_enabled;
	int			 have_sections = 0;
	int			 have_envelope =
	    (c->fetch_attrs & MBOX_FETCH_ENVELOPE) && c->pending_envelope_found;
	int			 have_bodystructure =
	    (c->fetch_attrs & MBOX_FETCH_BODYSTRUCTURE) &&
	    c->pending_bodystructure_found;

	for (i = 0; i < c->fetch_nslots; i++)
		if (c->fetch_slots[i].found)
			have_sections = 1;

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

	if (have_sections || have_envelope || have_bodystructure) {
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
		session_send_fetch_sections(s, need_sp);
		session_write(s, ")\r\n", 3);
	} else if (need_sp) {
		line_append(buf, sizeof(buf), &len, ")");
		session_untagged(s, buf);
	}

	fetch_slots_done(s);

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
	if (s->cmd.cmd_by_uid || s->condstore_enabled)
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
	uint32_t		 nranges, i;
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
	req.nsections = fa.nsections;
	for (i = 0; i < fa.nsections; i++)
		req.sections[i] = fa.sections[i].rec;
	fetch_set_labels(&s->cmd, &fa);

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
	s->cmd.fetch_limit = fa.limit;
	s->state = SESSION_FETCHING;

	if (send_mbox_request(s, IMSG_MBOX_FETCH, "IMSG_MBOX_FETCH", &req,
	    sizeof(req), ranges, nranges, sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
		return;
	}

}
