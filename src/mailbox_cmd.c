#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"
#include "mboxname.h"
#include "utf8.h"

/* CREATE, DELETE, SUBSCRIBE and UNSUBSCRIBE differ only here. */
struct mbox_simple_op {
	const char		*cmd;
	int			 type;
	const char		*imsgname;
	enum session_state	 state;
	int			 utf8;
	const char		*inbox_status;
	const char		*inbox_text;
	const char		*invalid_text;
};

static int	 parse_qresync_group(char *, struct imsg_mbox_select *,
		    struct seq_range[SEQSET_MAX_RANGES], uint32_t *,
		    const char **);
static int	 parse_select_params(char *, struct imsg_mbox_select *,
		    const struct session *, struct seq_range[SEQSET_MAX_RANGES],
		    uint32_t *, int *, const char **);
static void	 select_or_examine(struct session *, const char *, char *, int);
static void	 mbox_simple_op(struct session *, const char *, char *,
		    const struct mbox_simple_op *);
static int	 atom_char_ok(unsigned char, int);
static int	 parse_mailbox_arg(char **, char *, size_t, int, const char **);
static int	 parse_list_pattern(char **, char *, size_t, const char **);
static void	 list_dispatch(struct session *, const char *, char *, int);

static int
parse_qresync_group(char *inner, struct imsg_mbox_select *req,
    struct seq_range ranges[SEQSET_MAX_RANGES], uint32_t *nranges,
    const char **errmsg)
{
	const char	*errstr;
	uint32_t	 uidvalidity, i;
	uint64_t	 modseq;
	char		*p, *end, *tok;

	p = inner;
	if (*p == ' ') {
		*errmsg = "extra space";
		return (-1);
	}
	if (next_word(&p, &tok, errmsg) == -1)
		return (-1);
	if (parse_nz_number(tok, &uidvalidity) == -1) {
		*errmsg = "invalid QRESYNC uidvalidity";
		return (-1);
	}

	if (next_word(&p, &tok, errmsg) == -1)
		return (-1);
	if (*tok == '\0') {
		*errmsg = "QRESYNC requires uidvalidity and mod-sequence";
		return (-1);
	}
	if (*tok < '0' || *tok > '9') {
		*errmsg = "invalid QRESYNC mod-sequence";
		return (-1);
	}
	modseq = strtonum(tok, 1, MODSEQ_MAX, &errstr);
	if (errstr != NULL) {
		*errmsg = "invalid QRESYNC mod-sequence";
		return (-1);
	}

	req->qresync_uidvalidity = uidvalidity;
	req->qresync_modseq = modseq;
	req->qresync_has_uids = 0;

	if (*p == '\0')
		return (0);

	if (*p == '(') {
		*errmsg = "QRESYNC seq-match-data requires known-uids first";
		return (-1);
	}

	if (next_word(&p, &tok, errmsg) == -1)
		return (-1);
	if (parse_sequence_set(tok, ranges, nranges, errmsg) == -1)
		return (-1);
	for (i = 0; i < *nranges; i++) {
		if (ranges[i].lo_is_star || ranges[i].hi_is_star) {
			*errmsg = "invalid known-uids, '*' is not "
			    "allowed here";
			return (-1);
		}
	}
	req->qresync_has_uids = 1;
	req->qresync_nranges = *nranges;

	if (*p == '\0')
		return (0);

	if (*p != '(') {
		*errmsg = "expected seq-match-data";
		return (-1);
	}
	if ((end = match_paren(p)) == NULL) {
		*errmsg = "unterminated seq-match-data";
		return (-1);
	}
	p = end + 1;

	if (*p != '\0') {
		*errmsg = "unexpected data after QRESYNC arguments";
		return (-1);
	}

	return (0);
}

static int
parse_select_params(char *p, struct imsg_mbox_select *req,
    const struct session *s, struct seq_range ranges[SEQSET_MAX_RANGES],
    uint32_t *nranges, int *want_condstore, const char **errmsg)
{
	char	*q, *end;

	*want_condstore = 0;
	if (*p == '\0') {
		*errmsg = "empty select-param list";
		return (-1);
	}

	for (;;) {
		if (strncasecmp(p, "CONDSTORE", 9) == 0 &&
		    (p[9] == '\0' || p[9] == ' ')) {
			*want_condstore = 1;
			p += 9;
		} else if (strncasecmp(p, "QRESYNC", 7) == 0 &&
		    (p[7] == '\0' || p[7] == ' ')) {
			q = p + 7;

			if (read_sp(&q, errmsg) == -1)
				return (-1);
			if (*q != '(') {
				*errmsg = "QRESYNC requires a parenthesized "
				    "argument list";
				return (-1);
			}
			if (!s->qresync_enabled) {
				*errmsg = "QRESYNC requires ENABLE QRESYNC "
				    "first";
				return (-1);
			}

			if ((end = match_paren(q)) == NULL) {
				*errmsg = "unterminated QRESYNC argument list";
				return (-1);
			}
			*end = '\0';

			if (parse_qresync_group(q + 1, req, ranges, nranges,
			    errmsg) == -1)
				return (-1);

			req->qresync = 1;
			/* QRESYNC implies CONDSTORE. */
			*want_condstore = 1;
			p = end + 1;
		} else {
			*errmsg = "unrecognized SELECT parameter";
			return (-1);
		}
		if (*p == '\0')
			break;
		if (read_sp(&p, errmsg) == -1)
			return (-1);
	}

	return (0);
}

static void
select_or_examine(struct session *s, const char *tag, char *args, int readonly)
{
	struct imsg_mbox_select	 req;
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	const char		*errmsg;
	const char		*cmdname;
	uint32_t		 nranges = 0;
	size_t			 plen;
	char			 mailbox[MBOX_NAME_MAX], text[40];
	char			*params, *p;
	int			 want_condstore = 0;

	cmdname = readonly ? "EXAMINE" : "SELECT";
	if (args == NULL) {
		snprintf(text, sizeof(text), "%s requires a mailbox name",
		    cmdname);
		session_reply(s, tag, "BAD", text);
		return;
	}

	p = args;
	if (parse_mailbox_name(&p, mailbox, sizeof(mailbox), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	params = NULL;
	if (*p != '\0') {
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		params = p;
	}

	/* An empty name parses, so the reply is NO. */
	if (mailbox[0] == '\0') {
		session_reply(s, tag, "NO", "[NONEXISTENT] no such mailbox");
		return;
	}

	memset(&req, 0, sizeof(req));
	strlcpy(req.mailbox, mailbox, sizeof(req.mailbox));
	req.readonly = readonly;

	if (params != NULL) {
		plen = strlen(params);
		if (plen < 2 || params[0] != '(' || params[plen - 1] != ')') {
			session_reply(s, tag, "BAD",
			    "malformed select-param list");
			return;
		}
		params[plen - 1] = '\0';

		if (parse_select_params(params + 1, &req, s, ranges, &nranges,
		    &want_condstore, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (want_condstore)
		s->condstore_enabled = 1;

	if (s->state == SESSION_SELECTED)
		session_untagged(s,
		    "OK [CLOSED] previous mailbox closed");

	strlcpy(s->selected_mailbox, mailbox, sizeof(s->selected_mailbox));
	s->state = SESSION_SELECTING;
	s->mbox_readonly = readonly;

	if (send_mbox_request(s, IMSG_MBOX_SELECT, "IMSG_MBOX_SELECT", &req,
	    sizeof(req), ranges, nranges, sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_AUTHENTICATED;
		return;
	}

}

void
cmd_select(struct session *s, const char *tag, char *args)
{
	select_or_examine(s, tag, args, 0);
}

void
cmd_examine(struct session *s, const char *tag, char *args)
{
	select_or_examine(s, tag, args, 1);
}

/*
 * Checked here to save a round trip.  The store checks again.
 */
int
listener_mailbox_name_valid(const char *name)
{
	return (mailbox_name_syntax_ok(name));
}

int
listener_check_utf8(struct session *s, const char *tag, const char *name)
{
	if (utf8_mailbox_ok(name))
		return (1);

	log_debug("session %u: mailbox name not valid UTF-8", s->id);
	session_reply(s, tag, "NO",
	    "[CANNOT] mailbox name is not valid UTF-8");
	return (0);
}

static const struct mbox_simple_op op_create = {
	"CREATE", IMSG_MBOX_CREATE, "IMSG_MBOX_CREATE", SESSION_CREATING, 1,
	"NO", "[CANNOT] cannot create INBOX", "[CANNOT] invalid mailbox name"
}, op_delete = {
	/* An invalid name never existed, so NONEXISTENT. */
	"DELETE", IMSG_MBOX_DELETE, "IMSG_MBOX_DELETE", SESSION_DELETING, 0,
	"NO", "[CANNOT] cannot delete INBOX", "[NONEXISTENT] no such mailbox"
}, op_subscribe = {
	/* INBOX is treated as always subscribed. */
	"SUBSCRIBE", IMSG_MBOX_SUBSCRIBE, "IMSG_MBOX_SUBSCRIBE",
	SESSION_SUBSCRIBING, 1,
	"OK", "SUBSCRIBE completed", "[CANNOT] invalid mailbox name"
}, op_unsubscribe = {
	"UNSUBSCRIBE", IMSG_MBOX_UNSUBSCRIBE, "IMSG_MBOX_UNSUBSCRIBE",
	SESSION_UNSUBSCRIBING, 1,
	"NO", "[CANNOT] cannot unsubscribe INBOX",
	"[CANNOT] invalid mailbox name"
};

/*
 * A refused name is NO, not BAD.
 */
static void
mbox_simple_op(struct session *s, const char *tag, char *args,
    const struct mbox_simple_op *op)
{
	struct imsg_mbox_name	 req;
	const char		*errmsg;
	char			 mailbox[MBOX_NAME_MAX], text[64];
	char			*p;

	if (args == NULL) {
		snprintf(text, sizeof(text), "%s requires a mailbox name",
		    op->cmd);
		session_reply(s, tag, "BAD", text);
		return;
	}

	p = args;
	if (parse_mailbox_name(&p, mailbox, sizeof(mailbox), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	if (op->utf8 && !listener_check_utf8(s, tag, mailbox))
		return;
	if (mailbox_name_is_inbox(mailbox)) {
		session_reply(s, tag, op->inbox_status, op->inbox_text);
		return;
	}
	if (!listener_mailbox_name_valid(mailbox)) {
		session_reply(s, tag, "NO", op->invalid_text);
		return;
	}
	if (*p != '\0') {
		session_reply(s, tag, "BAD",
		    "trailing garbage after mailbox name");
		return;
	}

	memset(&req, 0, sizeof(req));
	strlcpy(req.mailbox, mailbox, sizeof(req.mailbox));
	strlcpy(s->cmd.mbox_op_name, mailbox, sizeof(s->cmd.mbox_op_name));
	s->cmd.mbox_op_prev_state = s->state;
	s->state = op->state;

	/* A failed send must not leave the session busy. */
	if (send_mbox_request(s, op->type, op->imsgname, &req, sizeof(req),
	    NULL, 0, 0) == -1) {
		s->state = s->cmd.mbox_op_prev_state;
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
	}
}

void
cmd_create(struct session *s, const char *tag, char *args)
{
	mbox_simple_op(s, tag, args, &op_create);
}

void
cmd_delete(struct session *s, const char *tag, char *args)
{
	mbox_simple_op(s, tag, args, &op_delete);
}

void
cmd_rename(struct session *s, const char *tag, char *args)
{
	struct imsg_mbox_rename	 req;
	const char		*errmsg;
	char			 oldname[MBOX_NAME_MAX];
	char			 newname[MBOX_NAME_MAX];
	char			*p;

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "RENAME requires two mailbox names");
		return;
	}

	p = args;
	if (parse_mailbox_name(&p, oldname, sizeof(oldname), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (parse_mailbox_name(&p, newname, sizeof(newname), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}

	if (mailbox_name_is_inbox(oldname)) {
		/* Clients must handle a NO for this. */
		session_reply(s, tag, "NO", "[CANNOT] cannot rename INBOX");
		return;
	}
	if (!listener_mailbox_name_valid(oldname)) {
		session_reply(s, tag, "NO", "[NONEXISTENT] no such mailbox");
		return;
	}
	if (!listener_check_utf8(s, tag, newname))
		return;
	if (mailbox_name_is_inbox(newname) ||
	    !listener_mailbox_name_valid(newname)) {
		session_reply(s, tag, "NO", "[CANNOT] invalid mailbox name");
		return;
	}

	if (*p != '\0') {
		session_reply(s, tag, "BAD",
		    "trailing garbage after mailbox name");
		return;
	}

	memset(&req, 0, sizeof(req));
	strlcpy(req.oldname, oldname, sizeof(req.oldname));
	strlcpy(req.newname, newname, sizeof(req.newname));
	strlcpy(s->cmd.mbox_op_name, oldname, sizeof(s->cmd.mbox_op_name));
	strlcpy(s->cmd.rename_newname, newname, sizeof(s->cmd.rename_newname));
	s->cmd.mbox_op_prev_state = s->state;
	s->state = SESSION_RENAMING;

	if (send_mbox_request(s, IMSG_MBOX_RENAME,
	    "IMSG_MBOX_RENAME", &req, sizeof(req), NULL, 0, 0) == -1) {
		s->state = s->cmd.mbox_op_prev_state;
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		return;
	}

}

void
cmd_subscribe(struct session *s, const char *tag, char *args)
{
	mbox_simple_op(s, tag, args, &op_subscribe);
}

void
cmd_unsubscribe(struct session *s, const char *tag, char *args)
{
	mbox_simple_op(s, tag, args, &op_unsubscribe);
}

/*
 * In a flat namespace, % matches like *.
 */
int
list_pattern_match(const char *pat, const char *name, int ci)
{
	const char	*p = pat;
	const char	*s = name;
	const char	*star_p = NULL;
	const char	*star_s = NULL;

	/* Two pointers and no recursion, so O(n*m) at worst. */
	while (*s != '\0') {
		if (*p == '*' || *p == '%') {
			while (*p == '*' || *p == '%')
				p++;
			star_p = p;
			star_s = s;
		} else if (*p != '\0' && (ci ?
		    toupper((unsigned char)*p) == toupper((unsigned char)*s) :
		    *p == *s)) {
			p++;
			s++;
		} else if (star_p != NULL) {
			star_s++;
			s = star_s;
			p = star_p;
		} else {
			return (0);
		}
	}

	while (*p == '*' || *p == '%')
		p++;
	return (*p == '\0');
}

int
quote_mailbox(char *out, size_t outsize, const char *name)
{
	size_t	i, o = 0, need;
	char	c;

	if (outsize < 3) {		/* Two DQUOTEs and a NUL. */
		if (outsize > 0)
			out[0] = '\0';
		return (-1);
	}

	out[o++] = '"';
	for (i = 0; name[i] != '\0'; i++) {
		c = name[i];

		/* A quoted string holds no CR or LF. */
		if (c == '\r' || c == '\n')
			c = ' ';

		need = (c == '"' || c == '\\') ? 2 : 1;
		/* The bytes, the closing DQUOTE and the NUL. */
		if (o + need + 2 > outsize) {
			out[o++] = '"';
			out[o] = '\0';
			return (-1);
		}
		if (need == 2)
			out[o++] = '\\';
		out[o++] = c;
	}
	out[o++] = '"';
	out[o] = '\0';
	return (0);
}

static int
atom_char_ok(unsigned char c, int wildcards)
{
	if (c <= 0x20 || c == 0x7f)		/* CTL or SP. */
		return (0);
	if (c == '(' || c == ')' || c == '{' || c == '"' || c == '\\')
		return (0);
	if ((c == '%' || c == '*') && !wildcards)
		return (0);
	return (1);
}

/*
 * An astring, or with wildcards set a list-mailbox.
 */
static int
parse_mailbox_arg(char **pp, char *out, size_t outsize, int wildcards,
    const char **errmsg)
{
	size_t	 o = 0, len;
	char	*p = *pp, *lit;

	if (*p == '\0') {
		*errmsg = wildcards ? "missing LIST pattern" :
		    "missing mailbox name";
		return (-1);
	}

	if (*p == '{') {
		if (read_literal(&p, &lit, &len, errmsg) == -1)
			return (-1);
		if (len >= outsize) {
			*errmsg = "mailbox name too long";
			return (-1);
		}
		memcpy(out, lit, len);
		out[len] = '\0';
		*pp = p;
		return (0);
	}

	if (*p == '"') {
		if (read_quoted(p, out, outsize, &o, &len, errmsg) == -1)
			return (-1);
		if (o >= outsize) {
			*errmsg = "mailbox name too long";
			return (-1);
		}
		p += len;
	} else {
		while (*p != '\0' && *p != ' ') {
			if (!atom_char_ok((unsigned char)*p, wildcards)) {
				*errmsg = wildcards ?
				    "invalid character in "
				    "unquoted LIST pattern" :
				    "invalid character in "
				    "unquoted mailbox name";
				return (-1);
			}
			if (o + 1 >= outsize) {
				*errmsg = "mailbox name too long";
				return (-1);
			}
			out[o++] = *p++;
		}
	}

	out[o] = '\0';
	*pp = p;
	return (0);
}

int
parse_mailbox_name(char **pp, char *out, size_t outsize, const char **errmsg)
{
	return (parse_mailbox_arg(pp, out, outsize, 0, errmsg));
}

static int
parse_list_pattern(char **pp, char *out, size_t outsize, const char **errmsg)
{
	return (parse_mailbox_arg(pp, out, outsize, 1, errmsg));
}

/*
 * Basic LIST syntax only.  LSUB differs only in its output.
 */
static void
list_dispatch(struct session *s, const char *tag, char *args, int is_lsub)
{
	struct imsg_mbox_list	 req;
	const char		*errmsg;
	const char		*cmdname = is_lsub ? "LSUB" : "LIST";
	size_t			 n;
	char			 reference[MBOX_NAME_MAX];
	char			 pattern[MBOX_NAME_MAX];
	char			 canon[2 * MBOX_NAME_MAX];
	char			 text[64];
	char			*p;
	int			 subscribed_only = 0;

	if (args == NULL) {
		snprintf(text, sizeof(text), "%s requires two arguments",
		    cmdname);
		session_reply(s, tag, "BAD", text);
		return;
	}

	p = args;
	if (*p == '(') {
		if (is_lsub) {
			session_reply(s, tag, "BAD",
			    "LSUB takes no selection options");
			return;
		}
		p++;
		/* An empty option list is legal, asking for nothing. */
		if (strncasecmp(p, "SUBSCRIBED", 10) == 0 &&
		    (p[10] == ')' || p[10] == ' ')) {
			subscribed_only = 1;
			p += 10;
		}
		if (*p == ' ' && (p[-1] == '(' || p[1] == ' ' || p[1] == ')')) {
			session_reply(s, tag, "BAD", "extra space");
			return;
		}
		if (*p != ')') {
			snprintf(text, sizeof(text),
			    "unsupported %s selection option", cmdname);
			session_reply(s, tag, "NO", text);
			return;
		}
		p++;
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (parse_mailbox_name(&p, reference, sizeof(reference), &errmsg) ==
	    -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}

	if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}

	if (*p == '(') {
		snprintf(text, sizeof(text),
		    "extended %s mailbox-pattern lists not supported",
		    cmdname);
		session_reply(s, tag, "NO", text);
		return;
	}

	if (parse_list_pattern(&p, pattern, sizeof(pattern), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}

	if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (*p != '\0') {
		snprintf(text, sizeof(text),
		    "extended %s return options not supported", cmdname);
		session_reply(s, tag, "NO", text);
		return;
	}

	/* An empty pattern asks for the hierarchy delimiter. */
	if (pattern[0] == '\0') {
		snprintf(text, sizeof(text), "%s (\\Noselect) \"/\" \"\"",
		    cmdname);
		session_untagged(s, text);
		snprintf(text, sizeof(text), "%s completed", cmdname);
		session_reply(s, tag, "OK", text);
		return;
	}

	n = strlcpy(canon, reference, sizeof(canon));
	if (n < sizeof(canon))
		n = strlcat(canon, pattern, sizeof(canon));
	if (n >= sizeof(canon)) {
		session_reply(s, tag, "BAD",
		    "combined reference and pattern too long");
		return;
	}

	/* INBOX is answered here, not by the store. */
	if (list_pattern_match(canon, "INBOX", 1)) {
		/* An empty attribute list is legal. */
		snprintf(text, sizeof(text), "%s (%s) \"/\" \"INBOX\"", cmdname,
		    subscribed_only ? "\\Subscribed" : "");
		session_untagged(s, text);
	}

	strlcpy(s->cmd.list_pattern, canon, sizeof(s->cmd.list_pattern));
	s->cmd.list_is_lsub = is_lsub;
	/* LSUB lists only subscribed names. */
	s->cmd.list_subscribed_only = subscribed_only || is_lsub;
	s->cmd.mbox_op_prev_state = s->state;
	s->state = SESSION_LISTING;

	memset(&req, 0, sizeof(req));
	req.subscribed_only = s->cmd.list_subscribed_only;

	if (send_mbox_request(s, IMSG_MBOX_LIST, "IMSG_MBOX_LIST",
	    &req, sizeof(req), NULL, 0, 0) == -1) {
		s->state = s->cmd.mbox_op_prev_state;
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		return;
	}

}

void
cmd_list(struct session *s, const char *tag, char *args)
{
	list_dispatch(s, tag, args, 0);
}

void
cmd_lsub(struct session *s, const char *tag, char *args)
{
	list_dispatch(s, tag, args, 1);
}

void
cmd_namespace(struct session *s, const char *tag, char *args)
{
	session_untagged(s, "NAMESPACE ((\"\" \"/\")) NIL NIL");
	session_reply(s, tag, "OK", "NAMESPACE completed");
}

void
cmd_status(struct session *s, const char *tag, char *args)
{
	struct imsg_mbox_status	 req;
	const char		*errmsg;
	uint32_t		 attrs = 0;
	size_t			 plen;
	char			 mailbox[MBOX_NAME_MAX];
	char			*p, *atts, *tok;
	char			 attbuf[256];

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "STATUS requires a mailbox name and status-att list");
		return;
	}

	p = args;
	if (parse_mailbox_name(&p, mailbox, sizeof(mailbox), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}

	if (*p != '\0' && read_sp(&p, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	atts = p;
	plen = strlen(atts);
	if (plen < 2 || atts[0] != '(' || atts[plen - 1] != ')') {
		session_reply(s, tag, "BAD",
		    "STATUS requires a parenthesized status-att list");
		return;
	}
	atts[plen - 1] = '\0';
	atts++;

	if (strlcpy(attbuf, atts, sizeof(attbuf)) >= sizeof(attbuf)) {
		session_reply(s, tag, "BAD", "status-att list too long");
		return;
	}
	p = (attbuf[0] != '\0') ? attbuf : NULL;
	while ((tok = strsep(&p, " ")) != NULL) {
		if (*tok == '\0') {
			session_reply(s, tag, "BAD", "extra space");
			return;
		}
		if (strcasecmp(tok, "MESSAGES") == 0)
			attrs |= STATUS_ATT_MESSAGES;
		else if (strcasecmp(tok, "UIDNEXT") == 0)
			attrs |= STATUS_ATT_UIDNEXT;
		else if (strcasecmp(tok, "UIDVALIDITY") == 0)
			attrs |= STATUS_ATT_UIDVALIDITY;
		else if (strcasecmp(tok, "UNSEEN") == 0)
			attrs |= STATUS_ATT_UNSEEN;
		else if (strcasecmp(tok, "DELETED") == 0)
			attrs |= STATUS_ATT_DELETED;
		else if (strcasecmp(tok, "SIZE") == 0)
			attrs |= STATUS_ATT_SIZE;
		else if (strcasecmp(tok, "HIGHESTMODSEQ") == 0)
			attrs |= STATUS_ATT_HIGHESTMODSEQ;
		else if (strcasecmp(tok, "RECENT") == 0)
			/* IMAP4rev2 dropped RECENT, but clients still ask. */
			attrs |= STATUS_ATT_RECENT;
		else {
			session_reply(s, tag, "BAD", "unknown status-att");
			return;
		}
	}

	if (attrs == 0) {
		session_reply(s, tag, "BAD",
		    "STATUS requires at least one status-att");
		return;
	}

	if (!mailbox_name_is_inbox(mailbox) &&
	    !listener_mailbox_name_valid(mailbox)) {
		/* A malformed name never existed, so NONEXISTENT. */
		session_reply(s, tag, "NO", "[NONEXISTENT] no such mailbox");
		return;
	}

	if (attrs & STATUS_ATT_HIGHESTMODSEQ)
		session_condstore_enable(s);

	memset(&req, 0, sizeof(req));
	strlcpy(req.mailbox, mailbox, sizeof(req.mailbox));
	strlcpy(s->cmd.status_mailbox, mailbox, sizeof(s->cmd.status_mailbox));
	req.attrs = attrs;
	s->cmd.status_attrs = attrs;
	s->cmd.status_prev_state = s->state;
	s->state = SESSION_STATUSING;

	if (send_mbox_request(s, IMSG_MBOX_STATUS,
	    "IMSG_MBOX_STATUS", &req, sizeof(req), NULL, 0, 0) == -1) {
		s->state = s->cmd.status_prev_state;
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		return;
	}

}
