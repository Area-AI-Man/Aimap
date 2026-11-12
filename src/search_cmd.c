#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"

#define SEARCH_MAX_DEPTH	64
struct search_parse_ctx {
	struct search_node	nodes[SEARCH_PROGRAM_MAX_NODES];
	uint32_t		n;
	int			depth;
	int			uses_modseq;
	/* Octets of all string operands, counted past the cap. */
	size_t			operand_len;
	char			pool[SEARCH_OPERANDS_MAX];
};

/* The operand that follows each search key. */
enum search_arg {
	SARG_NONE,
	SARG_KEYWORD,
	SARG_DATE,
	SARG_NUMBER,
	SARG_MODSEQ,
	SARG_STRING,
	SARG_HEADER,
	SARG_UIDSET,
	SARG_KEY,
	SARG_KEY2
};

static int	 parse_search_key_inner(char **, struct search_parse_ctx *,
		    const char **);
static int	 parse_search_key_list(char **, struct search_parse_ctx *,
		    const char **, int);
static void	 search_dispatch_finish(struct session *,
		    const struct search_parse_result *, struct search_node *);
static int	 parse_search_date(const char *, int64_t *);
static int	 search_push(struct search_parse_ctx *,
		    const struct search_node *, const char **);
static int	 parse_search_seqset(char **, struct search_parse_ctx *, int,
		    const char **);
static int	 parse_search_key(char **, struct search_parse_ctx *,
		    const char **);
static int	 read_search_token(char **, char *, size_t, const char *,
		    const char **);
static int	 read_search_date(char **, int64_t *, const char **);
static void	 search_pool_add(struct search_parse_ctx *, char);
static int	 read_search_astring(char **, struct search_parse_ctx *,
		    uint32_t *, uint32_t *, const char **);
static int	 read_search_number(char **, int64_t *, int, const char **);
static int	 skip_modseq_entry(char **, const char **);
static int	 search_program_parse(char *, struct search_node *, uint32_t *,
		    int *, char *, uint32_t *, const char **);
static int	 parse_search_return_opts(char **, uint32_t *, const char **);
static int	 read_search_charset(char **, char *, size_t);
static void	 search_saved_clear(struct session *, uint32_t);

static int
parse_search_date(const char *s, int64_t *out)
{
	static const char	shape[] = "-aaa-dddd";
	struct tm		tm;
	time_t			t;
	const char		*p;
	char			mon[4];
	int			day, year, i;

	memset(&tm, 0, sizeof(tm));
	for (p = s; p - s < 2 && isdigit((unsigned char)*p); p++)
		;
	if (p == s || strlen(p) != sizeof(shape) - 1)
		return (-1);
	for (i = 0; shape[i] != '\0'; i++) {
		switch (shape[i]) {
		case 'a':
			if (!isalpha((unsigned char)p[i]))
				return (-1);
			break;
		case 'd':
			if (!isdigit((unsigned char)p[i]))
				return (-1);
			break;
		default:
			if (p[i] != shape[i])
				return (-1);
			break;
		}
	}

	day = (p - s == 1) ? s[0] - '0' : (s[0] - '0') * 10 + (s[1] - '0');
	year = (p[5] - '0') * 1000 + (p[6] - '0') * 100 +
	    (p[7] - '0') * 10 + (p[8] - '0');
	memcpy(mon, p + 1, 3);
	mon[3] = '\0';

	if (day < 1 || day > 31 || year < 1970)
		return (-1);

	for (i = 0; i < 12; i++) {
		if (strcasecmp(mon, fetch_month_names[i]) == 0)
			break;
	}
	if (i == 12)
		return (-1);

	tm.tm_mday = day;
	tm.tm_mon = i;
	tm.tm_year = year - 1900;

	if ((t = timegm(&tm)) == (time_t)-1)
		return (-1);

	*out = (int64_t)t;
	return (0);
}

static int
search_push(struct search_parse_ctx *ctx, const struct search_node *node,
    const char **errmsg)
{
	if (ctx->n >= SEARCH_PROGRAM_MAX_NODES) {
		*errmsg = "search criteria too complex";
		return (-1);
	}
	ctx->nodes[ctx->n++] = *node;
	return (0);
}

/*
 * Push one node per range, ORed together.
 */
static int
parse_search_seqset(char **pp, struct search_parse_ctx *ctx, int op,
    const char **errmsg)
{
	struct search_node	 node, combine;
	char			*p = *pp;
	const char		*start = p;
	char			 tok[SESSION_INBUF_MAX];
	size_t			 len;
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	uint32_t		 nranges, i;

	while (*p != '\0' && *p != ' ' && *p != ')')
		p++;

	if (p == start) {
		*errmsg = "missing sequence set";
		return (-1);
	}

	len = (size_t)(p - start);
	if (len >= sizeof(tok)) {
		*errmsg = "sequence set too long";
		return (-1);
	}
	memcpy(tok, start, len);
	tok[len] = '\0';

	if (parse_sequence_set(tok, ranges, &nranges, errmsg) == -1)
		return (-1);

	for (i = 0; i < nranges; i++) {
		memset(&node, 0, sizeof(node));
		node.op = SEQ_RANGE_SAVED(&ranges[i]) ? SEARCH_OP_SAVED : op;
		node.seq_lo = ranges[i].lo;
		node.seq_hi = ranges[i].hi;
		node.lo_is_star = ranges[i].lo_is_star;
		node.hi_is_star = ranges[i].hi_is_star;
		if (search_push(ctx, &node, errmsg) == -1)
			return (-1);

		if (i > 0) {
			memset(&combine, 0, sizeof(combine));
			combine.op = SEARCH_OP_OR;
			if (search_push(ctx, &combine, errmsg) == -1)
				return (-1);
		}
	}

	*pp = p;
	return (0);
}

static int
parse_search_key(char **pp, struct search_parse_ctx *ctx, const char **errmsg)
{
	int	rc;

	if (++ctx->depth > SEARCH_MAX_DEPTH) {
		ctx->depth--;
		*errmsg = "search criteria nested too deeply";
		return (-1);
	}
	rc = parse_search_key_inner(pp, ctx, errmsg);
	ctx->depth--;
	return (rc);
}

static int
read_search_token(char **pp, char *buf, size_t bufsize, const char *errtext,
    const char **errmsg)
{
	const char	*start;
	char		*p = *pp;

	start = p;
	while (*p != '\0' && *p != ' ' && *p != ')')
		p++;
	if (p == start || (size_t)(p - start) >= bufsize) {
		*errmsg = errtext;
		return (-1);
	}
	memcpy(buf, start, (size_t)(p - start));
	buf[p - start] = '\0';
	*pp = p;
	return (0);
}

/*
 * Return the date as the UTC midnight starting it.
 */
static int
read_search_date(char **pp, int64_t *out, const char **errmsg)
{
	const char	*start;
	size_t		 len;
	char		*p = *pp, *end;
	char		 datebuf[32];

	if (*p == '"') {
		start = p + 1;

		end = strchr(start, '"');
		if (end == NULL) {
			*errmsg = "unterminated date string";
			return (-1);
		}
		len = (size_t)(end - start);
		if (len >= sizeof(datebuf)) {
			*errmsg = "malformed date";
			return (-1);
		}
		memcpy(datebuf, start, len);
		datebuf[len] = '\0';
		p = end + 1;
	} else {
		if (read_search_token(&p, datebuf, sizeof(datebuf),
		    "malformed date", errmsg) == -1)
			return (-1);
	}

	if (parse_search_date(datebuf, out) == -1) {
		*errmsg = "malformed date";
		return (-1);
	}
	*pp = p;
	return (0);
}

static void
search_pool_add(struct search_parse_ctx *ctx, char c)
{
	if (ctx->operand_len < sizeof(ctx->pool))
		ctx->pool[ctx->operand_len] = c;
	ctx->operand_len++;
}

static int
read_search_astring(char **pp, struct search_parse_ctx *ctx,
    uint32_t *offp, uint32_t *lenp, const char **errmsg)
{
	size_t	 start = ctx->operand_len, len, used, room, i;
	char	*p = *pp, *lit;

	if (*p == '{') {
		if (read_literal(&p, &lit, &len, errmsg) == -1)
			return (-1);
		for (i = 0; i < len; i++)
			search_pool_add(ctx, lit[i]);
	} else if (*p == '"') {
		/* Once the pool is full, only count the octets. */
		room = 0;
		if (start < sizeof(ctx->pool))
			room = sizeof(ctx->pool) - start;
		if (read_quoted(p, ctx->pool + (room > 0 ? start : 0), room,
		    &len, &used, errmsg) == -1)
			return (-1);
		ctx->operand_len += len;
		p += used;
	} else {
		/* RFC 9051 section 9 ASTRING-CHAR. */
		for (; *p != '\0' && *p != ' ' && *p != ')'; p++) {
			if ((unsigned char)*p <= 0x1f ||
			    (unsigned char)*p >= 0x7f ||
			    strchr("({%*\"\\", *p) != NULL) {
				*errmsg = "malformed search string";
				return (-1);
			}
			search_pool_add(ctx, *p);
		}
		if (ctx->operand_len == start) {
			*errmsg = "missing search string";
			return (-1);
		}
	}
	/* Valid only if the total stays under the cap. */
	*offp = (uint32_t)start;
	*lenp = (uint32_t)(ctx->operand_len - start);
	*pp = p;
	return (0);
}

static const struct search_keyword {
	const char	*name;
	int		 op;
	enum search_arg	 arg;
} search_keywords[] = {
	{ "ALL",	SEARCH_OP_ALL,		SARG_NONE },
	{ "ANSWERED",	SEARCH_OP_ANSWERED,	SARG_NONE },
	{ "UNANSWERED",	SEARCH_OP_UNANSWERED,	SARG_NONE },
	{ "DELETED",	SEARCH_OP_DELETED,	SARG_NONE },
	{ "UNDELETED",	SEARCH_OP_UNDELETED,	SARG_NONE },
	{ "DRAFT",	SEARCH_OP_DRAFT,	SARG_NONE },
	{ "UNDRAFT",	SEARCH_OP_UNDRAFT,	SARG_NONE },
	{ "FLAGGED",	SEARCH_OP_FLAGGED,	SARG_NONE },
	{ "UNFLAGGED",	SEARCH_OP_UNFLAGGED,	SARG_NONE },
	{ "SEEN",	SEARCH_OP_SEEN,		SARG_NONE },
	{ "UNSEEN",	SEARCH_OP_UNSEEN,	SARG_NONE },
	{ "KEYWORD",	SEARCH_OP_KEYWORD,	SARG_KEYWORD },
	{ "UNKEYWORD",	SEARCH_OP_UNKEYWORD,	SARG_KEYWORD },
	{ "BEFORE",	SEARCH_OP_BEFORE,	SARG_DATE },
	{ "ON",		SEARCH_OP_ON,		SARG_DATE },
	{ "SINCE",	SEARCH_OP_SINCE,	SARG_DATE },
	{ "LARGER",	SEARCH_OP_LARGER,	SARG_NUMBER },
	{ "SMALLER",	SEARCH_OP_SMALLER,	SARG_NUMBER },
	{ "UID",	SEARCH_OP_UIDSET,	SARG_UIDSET },
	{ "MODSEQ",	SEARCH_OP_MODSEQ,	SARG_MODSEQ },
	{ "NOT",	SEARCH_OP_NOT,		SARG_KEY },
	{ "OR",		SEARCH_OP_OR,		SARG_KEY2 },
	{ "SENTBEFORE",	SEARCH_OP_SENTBEFORE,	SARG_DATE },
	{ "SENTON",	SEARCH_OP_SENTON,	SARG_DATE },
	{ "SENTSINCE",	SEARCH_OP_SENTSINCE,	SARG_DATE },
	{ "BCC",	SEARCH_OP_BCC,		SARG_STRING },
	{ "BODY",	SEARCH_OP_BODY,		SARG_STRING },
	{ "CC",		SEARCH_OP_CC,		SARG_STRING },
	{ "FROM",	SEARCH_OP_FROM,		SARG_STRING },
	{ "HEADER",	SEARCH_OP_HEADER,	SARG_HEADER },
	{ "SUBJECT",	SEARCH_OP_SUBJECT,	SARG_STRING },
	{ "TEXT",	SEARCH_OP_TEXT,		SARG_STRING },
	{ "TO",		SEARCH_OP_TO,		SARG_STRING },
};

static int
read_search_number(char **pp, int64_t *out, int modseq, const char **errmsg)
{
	const char	*errstr;
	char		 numbuf[24];

	if (read_search_token(pp, numbuf, sizeof(numbuf), modseq ?
	    "missing or malformed MODSEQ value" :
	    "missing or malformed octet count", errmsg) == -1)
		return (-1);
	errstr = "not a number";
	if (numbuf[0] >= '0' && numbuf[0] <= '9')
		*out = strtonum(numbuf, 0, INT64_MAX, &errstr);
	if (errstr != NULL) {
		*errmsg = modseq ? "malformed MODSEQ value" :
		    "malformed octet count";
		return (-1);
	}
	return (0);
}

/*
 * The optional entry name and type are ignored.
 */
static int
skip_modseq_entry(char **pp, const char **errmsg)
{
	char	*p = *pp, *end;

	if (*p == '\0' || isdigit((unsigned char)*p)) {
		*pp = p;
		return (0);
	}
	if (*p == '"') {
		if ((end = strchr(p + 1, '"')) == NULL) {
			*errmsg = "unterminated MODSEQ entry-name";
			return (-1);
		}
		p = end + 1;
	} else {
		while (*p != '\0' && *p != ' ' && *p != ')')
			p++;
	}
	if (read_sp(&p, errmsg) == -1)
		return (-1);

	if (strncasecmp(p, "priv", 4) == 0 &&
	    (p[4] == ' ' || p[4] == '\0' || p[4] == ')'))
		p += 4;
	else if (strncasecmp(p, "shared", 6) == 0 &&
	    (p[6] == ' ' || p[6] == '\0' || p[6] == ')'))
		p += 6;
	else if (strncasecmp(p, "all", 3) == 0 &&
	    (p[3] == ' ' || p[3] == '\0' || p[3] == ')'))
		p += 3;
	else {
		*errmsg = "expected priv/shared/all after MODSEQ entry-name";
		return (-1);
	}
	if (read_sp(&p, errmsg) == -1)
		return (-1);
	*pp = p;
	return (0);
}

static int
parse_search_key_inner(char **pp, struct search_parse_ctx *ctx,
    const char **errmsg)
{
	const struct search_keyword	*kw;
	struct search_node		 node;
	size_t				 wlen, i;
	char				*p = *pp, *start;
	char				 word[32];
	int				 rc;

	if (*p == ' ') {
		*errmsg = "extra space";
		return (-1);
	}
	if (*p == '\0') {
		*errmsg = "missing search key";
		return (-1);
	}

	if (*p == '(') {
		p++;
		if ((rc = parse_search_key_list(&p, ctx, errmsg, 1)) != 0)
			return (rc);
		if (*p != ')') {
			*errmsg = "unterminated parenthesized search key list";
			return (-1);
		}
		p++;
		*pp = p;
		return (0);
	}

	if (isdigit((unsigned char)*p) || *p == '*' || *p == '$') {
		if (parse_search_seqset(&p, ctx, SEARCH_OP_SEQSET, errmsg) ==
		    -1)
			return (-1);
		*pp = p;
		return (0);
	}

	start = p;
	while (*p != '\0' && *p != ' ' && *p != ')')
		p++;
	wlen = (size_t)(p - start);
	if (wlen == 0 || wlen >= sizeof(word)) {
		*errmsg = "unknown search key";
		return (-1);
	}
	memcpy(word, start, wlen);
	word[wlen] = '\0';

	kw = NULL;
	for (i = 0; i < nitems(search_keywords); i++) {
		if (strcasecmp(word, search_keywords[i].name) == 0) {
			kw = &search_keywords[i];
			break;
		}
	}
	if (kw == NULL) {
		*errmsg = "unknown search key";
		return (-1);
	}

	memset(&node, 0, sizeof(node));
	node.op = kw->op;
	if (kw->arg != SARG_NONE && read_sp(&p, errmsg) == -1)
		return (-1);
	switch (kw->arg) {
	case SARG_NONE:
		break;
	case SARG_KEYWORD:
		if (read_search_token(&p, node.keyword, sizeof(node.keyword),
		    "missing or too-long KEYWORD/UNKEYWORD argument",
		    errmsg) == -1)
			return (-1);
		break;
	case SARG_DATE:
		if (read_search_date(&p, &node.num, errmsg) == -1)
			return (-1);
		break;
	case SARG_NUMBER:
		if (read_search_number(&p, &node.num, 0, errmsg) == -1)
			return (-1);
		break;
	case SARG_MODSEQ:
		if (skip_modseq_entry(&p, errmsg) == -1 ||
		    read_search_number(&p, &node.num, 1, errmsg) == -1)
			return (-1);
		ctx->uses_modseq = 1;
		break;
	case SARG_HEADER:
	case SARG_STRING:
		if (kw->arg == SARG_HEADER && (read_search_astring(&p, ctx,
		    &node.name_off, &node.name_len, errmsg) == -1 ||
		    read_sp(&p, errmsg) == -1))
			return (-1);
		if (read_search_astring(&p, ctx, &node.str_off, &node.str_len,
		    errmsg) == -1)
			return (-1);
		break;
	case SARG_UIDSET:
		if (parse_search_seqset(&p, ctx, SEARCH_OP_UIDSET, errmsg) ==
		    -1)
			return (-1);
		*pp = p;
		return (0);	/* The set pushed its own nodes. */
	case SARG_KEY2:
		if ((rc = parse_search_key(&p, ctx, errmsg)) != 0)
			return (rc);
		if (read_sp(&p, errmsg) == -1)
			return (-1);
		/* FALLTHROUGH */
	case SARG_KEY:
		if ((rc = parse_search_key(&p, ctx, errmsg)) != 0)
			return (rc);
		break;
	}

	if (search_push(ctx, &node, errmsg) == -1)
		return (-1);
	*pp = p;
	return (0);
}

static int
parse_search_key_list(char **pp, struct search_parse_ctx *ctx,
    const char **errmsg, int in_parens)
{
	struct search_node	combine;
	char			*p;
	int			rc;

	rc = parse_search_key(pp, ctx, errmsg);
	if (rc != 0)
		return (rc);

	for (;;) {
		p = *pp;

		if (in_parens && *p == ')') {
			*pp = p;
			return (0);
		}
		if (*p == '\0') {
			if (in_parens) {
				*errmsg = "unterminated parenthesized search "
				    "key list";
				return (-1);
			}
			*pp = p;
			return (0);
		}
		if (!in_parens && *p == ')') {
			*errmsg = "unexpected ')'";
			return (-1);
		}
		if (read_sp(&p, errmsg) == -1)
			return (-1);
		if (*p == ')') {
			*errmsg = "extra space";
			return (-1);
		}

		*pp = p;
		rc = parse_search_key(pp, ctx, errmsg);
		if (rc != 0)
			return (rc);

		memset(&combine, 0, sizeof(combine));
		combine.op = SEARCH_OP_AND;
		if (search_push(ctx, &combine, errmsg) == -1)
			return (-1);
	}
}

static int
search_program_parse(char *args, struct search_node *nodes_out,
    uint32_t *nnodes_out, int *uses_modseq_out, char *pool_out,
    uint32_t *poollen_out, const char **errmsg_out)
{
	struct search_parse_ctx	 ctx;
	const char		*errmsg;
	char			*p = args;
	int			 rc;

	memset(&ctx, 0, sizeof(ctx));
	rc = parse_search_key_list(&p, &ctx, &errmsg, 0);
	if (rc == 0 && ctx.operand_len > SEARCH_OPERANDS_MAX) {
		errmsg = "[LIMIT] search strings exceed 4096 octets in all";
		rc = PARSE_NO;
	} else if (rc == 0 && ctx.n == 0) {
		errmsg = "SEARCH requires search criteria";
		rc = -1;
	}
	if (rc != 0) {
		*errmsg_out = errmsg;
		return (rc);
	}

	memcpy(nodes_out, ctx.nodes, ctx.n * sizeof(*nodes_out));
	*nnodes_out = ctx.n;
	*uses_modseq_out = ctx.uses_modseq;
	memcpy(pool_out, ctx.pool, ctx.operand_len);
	*poollen_out = (uint32_t)ctx.operand_len;
	return (0);
}

static int
parse_search_return_opts(char **pp, uint32_t *opts_out, const char **errmsg)
{
	const char	*start;
	size_t		len;
	char		*p = *pp, word[16];

	*opts_out = 0;
	p++;

	if (*p == ' ') {
		*errmsg = "extra space";
		return (-1);
	}
	if (*p == ')') {
		*pp = p + 1;
		return (0);
	}

	for (;;) {
		start = p;

		while (*p != '\0' && *p != ' ' && *p != ')')
			p++;
		len = (size_t)(p - start);
		if (len == 0 || len >= sizeof(word)) {
			*errmsg = "malformed SEARCH RETURN option";
			return (-1);
		}
		memcpy(word, start, len);
		word[len] = '\0';

		if (strcasecmp(word, "MIN") == 0)
			*opts_out |= SEARCH_RETURN_MIN;
		else if (strcasecmp(word, "MAX") == 0)
			*opts_out |= SEARCH_RETURN_MAX;
		else if (strcasecmp(word, "ALL") == 0)
			*opts_out |= SEARCH_RETURN_ALL;
		else if (strcasecmp(word, "COUNT") == 0)
			*opts_out |= SEARCH_RETURN_COUNT;
		else if (strcasecmp(word, "SAVE") == 0)
			*opts_out |= SEARCH_RETURN_SAVE;
		else {
			*errmsg = "unsupported SEARCH RETURN option";
			return (-1);
		}

		if (*p == ')') {
			*pp = p + 1;
			return (0);
		}
		if (*p == '\0') {
			*errmsg = "unterminated SEARCH RETURN option list";
			return (-1);
		}
		if (read_sp(&p, errmsg) == -1)
			return (-1);
		if (*p == ')') {
			*errmsg = "extra space";
			return (-1);
		}
	}
}

static int
read_search_charset(char **pp, char *out, size_t outsize)
{
	size_t	 o = 0;
	char	*p = *pp;

	if (*p == '"') {
		for (p++; *p != '"'; p++) {
			if (*p == '\0' ||
			    (*p == '\\' && *++p != '"' && *p != '\\'))
				return (-1);
			if (o + 1 >= outsize)
				return (-1);
			out[o++] = *p;
		}
		p++;
	} else {
		/* RFC 9051 section 9 ATOM-CHAR. */
		for (; *p != '\0' && *p != ' '; p++) {
			if ((unsigned char)*p <= 0x1f ||
			    (unsigned char)*p >= 0x7f ||
			    strchr("(){%*\"\\]", *p) != NULL ||
			    o + 1 >= outsize)
				return (-1);
			out[o++] = *p;
		}
		if (o == 0)
			return (-1);
	}
	if (*p != ' ' && *p != '\0')
		return (-1);
	out[o] = '\0';
	*pp = p;
	return (0);
}

/*
 * A SAVE answered NO empties the saved result.
 */
static void
search_saved_clear(struct session *s, uint32_t opts)
{
	if (opts & SEARCH_RETURN_SAVE)
		(void)send_mbox_request(s, IMSG_MBOX_SAVED_CLEAR,
		    "IMSG_MBOX_SAVED_CLEAR", NULL, 0, NULL, 0, 0);
}

void
cmd_search(struct session *s, const char *tag, char *args)
{
	search_dispatch(s, tag, args, 0);
}

void
search_dispatch(struct session *s, const char *tag, char *args, int by_uid)
{
	struct search_parse_result	 res;
	struct search_node		 nodes[SEARCH_PROGRAM_MAX_NODES];
	const char			*errmsg;
	uint32_t			 return_opts = 0;
	char				*p, charset[64];
	int				 rc;

	if (args == NULL) {
		session_reply(s, tag, "BAD", "SEARCH requires search criteria");
		return;
	}

	p = args;
	if (strncasecmp(p, "RETURN", 6) == 0 &&
	    (p[6] == ' ' || p[6] == '\0')) {
		p += 6;
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		if (*p != '(') {
			session_reply(s, tag, "BAD",
			    "malformed SEARCH RETURN option list");
			return;
		}
		rc = parse_search_return_opts(&p, &return_opts, &errmsg);
		if (rc == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (return_opts == 0)
		/* No RETURN options means ALL. */
		return_opts = SEARCH_RETURN_ALL;

	if (strncasecmp(p, "CHARSET", 7) == 0 &&
	    (p[7] == ' ' || p[7] == '\0')) {
		p += 7;
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		if (read_search_charset(&p, charset, sizeof(charset)) == -1) {
			session_reply(s, tag, "BAD", "malformed CHARSET");
			return;
		}

		if (strcasecmp(charset, "US-ASCII") != 0 &&
		    strcasecmp(charset, "UTF-8") != 0) {
			search_saved_clear(s, return_opts);
			/* The formal syntax requires the parentheses. */
			session_reply(s, tag, "NO",
			    "[BADCHARSET (US-ASCII UTF-8)] unsupported "
			    "CHARSET");
			return;
		}

		if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (strlen(p) >= SEARCH_ARGS_MAX) {
		session_reply(s, tag, "BAD", "SEARCH criteria too long");
		return;
	}

	memset(&res, 0, sizeof(res));
	res.rc = search_program_parse(p, nodes, &res.nnodes, &res.uses_modseq,
	    res.pool, &res.poollen, &res.errmsg);
	if (res.rc == -1 && res.errmsg == literal_wanted) {
		session_arg_error(s, tag, literal_wanted);
		return;
	}

	s->cmd.search_return_opts = return_opts;
	s->cmd.cmd_by_uid = by_uid;

	search_dispatch_finish(s, &res, res.nnodes > 0 ? nodes : NULL);

}

static void
search_dispatch_finish(struct session *s,
    const struct search_parse_result *res, struct search_node *nodes)
{
	struct imsg_mbox_search	 req;

	if (res->rc == -1) {
		session_reply(s, s->cmd.pending_tag, "BAD", res->errmsg);
		s->state = SESSION_SELECTED;
		return;
	}
	if (res->rc == PARSE_NO) {
		search_saved_clear(s, s->cmd.search_return_opts);
		session_reply(s, s->cmd.pending_tag, "NO", res->errmsg);
		s->state = SESSION_SELECTED;
		return;
	}

	s->cmd.search_used_modseq = res->uses_modseq;

	if (res->uses_modseq)
		session_condstore_enable(s);

	s->state = SESSION_SEARCHING;

	memset(&req, 0, sizeof(req));
	req.nnodes = res->nnodes;
	req.poollen = res->poollen;
	req.return_opts = s->cmd.search_return_opts;
	memcpy(req.pool, res->pool, res->poollen);

	if (send_mbox_request(s, IMSG_MBOX_SEARCH,
	    "IMSG_MBOX_SEARCH", &req, sizeof(req), nodes, res->nnodes,
	    sizeof(struct search_node)) == -1) {
		search_saved_clear(s, s->cmd.search_return_opts);
		session_reply(s, s->cmd.pending_tag, "NO",
		    "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
	}
}

void
session_handle_mbox_search_match(struct session *s,
    struct imsg_mbox_search_match *m)
{
	uint32_t	 newcap, *n;

	if (s->cmd.search_alloc_failed)
		return;

	if (s->cmd.search_nmatches == s->cmd.search_matches_cap) {
		newcap = s->cmd.search_matches_cap ?
		    s->cmd.search_matches_cap * 2 : 32;

		n = reallocarray(s->cmd.search_matches, newcap,
		    sizeof(uint32_t));
		if (n == NULL) {
			log_warn("session %u: realloc SEARCH match array",
			    s->id);
			s->cmd.search_alloc_failed = 1;
			return;
		}
		s->cmd.search_matches = n;
		s->cmd.search_matches_cap = newcap;
	}

	s->cmd.search_matches[s->cmd.search_nmatches++] = s->cmd.cmd_by_uid ?
	    m->uid : m->seqno;

	if (m->modseq > s->cmd.search_max_modseq)
		s->cmd.search_max_modseq = m->modseq;
}

#define SEARCH_RESP_PREFIX_MAX	256
#define SEARCH_ALL_PER_MATCH	11	/* Ten digits and a separator */

void
session_finish_search(struct session *s, struct imsg_mbox_result *res)
{
	size_t		 bufsize, len;
	char		*buf = NULL;
	int		 truncated = 0;

	s->state = SESSION_SELECTED;

	log_debug("session %u: SEARCH done, status=%s, %u match(es)", s->id,
	    res->error == MBOX_OP_OK ? "OK" : "ERROR", res->count);

	if (res->error == MBOX_OP_ERR_BUSY) {
		session_reply(s, s->cmd.pending_tag, "NO", IMAP_BUSY_TEXT);
		return;
	}
	if (res->error == MBOX_OP_ERR_NOTSAVED) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    "[NOTSAVED] too many results to save");
		return;
	}
	if (res->error != MBOX_OP_OK || s->cmd.search_alloc_failed)
		goto fail;
	/* SAVE alone suppresses the ESEARCH response. */
	if (s->cmd.search_return_opts == SEARCH_RETURN_SAVE)
		goto done;

	bufsize = SEARCH_RESP_PREFIX_MAX +
	    (size_t)s->cmd.search_nmatches * SEARCH_ALL_PER_MATCH + 1;
	if ((buf = malloc(bufsize)) == NULL) {
		log_warn("session %u: malloc SEARCH response buffer", s->id);
		goto fail;
	}

	len = 0;
	line_append(buf, bufsize, &len, "* ESEARCH (TAG \"%s\")",
	    s->cmd.pending_tag);

	/* The grammar puts UID before the result items. */
	if (s->cmd.cmd_by_uid)
		line_append(buf, bufsize, &len, " UID");

	if ((s->cmd.search_return_opts & SEARCH_RETURN_MIN) &&
	    s->cmd.search_nmatches > 0)
		line_append(buf, bufsize, &len, " MIN %u",
		    s->cmd.search_matches[0]);

	if ((s->cmd.search_return_opts & SEARCH_RETURN_MAX) &&
	    s->cmd.search_nmatches > 0)
		line_append(buf, bufsize, &len, " MAX %u",
		    s->cmd.search_matches[s->cmd.search_nmatches - 1]);

	if ((s->cmd.search_return_opts & SEARCH_RETURN_ALL) &&
	    s->cmd.search_nmatches > 0) {
		line_append(buf, bufsize, &len, " ALL ");
		len += format_seq_list(buf + len, bufsize - len,
		    s->cmd.search_matches, s->cmd.search_nmatches, &truncated);
		if (truncated)
			fatalx("session %u: SEARCH ALL truncated at %zu bytes",
			    s->id, bufsize);
	}

	if (s->cmd.search_return_opts & SEARCH_RETURN_COUNT)
		line_append(buf, bufsize, &len, " COUNT %u",
		    s->cmd.search_nmatches);

	if (s->cmd.search_used_modseq && s->cmd.search_nmatches > 0)
		line_append(buf, bufsize, &len, " MODSEQ %llu",
		    (unsigned long long)s->cmd.search_max_modseq);

	line_append(buf, bufsize, &len, "\r\n");
	session_write(s, buf, len);
	free(buf);

done:
	session_reply(s, s->cmd.pending_tag, "OK",
	    s->cmd.cmd_by_uid ? "UID SEARCH completed" : "SEARCH completed");
	return;

fail:
	free(buf);
	session_reply(s, s->cmd.pending_tag, "NO",
	    s->cmd.cmd_by_uid ? "UID SEARCH failed" : "SEARCH failed");
}
