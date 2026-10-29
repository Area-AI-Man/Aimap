#include <sys/types.h>

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

static void	 store_do(struct session *, const char *, char *, int);
static void	 session_request_expunge(struct session *, const char *,
		    int, int, const struct seq_range *, uint32_t);
static void	 uid_expunge_dispatch(struct session *, const char *,
		    const char *);
static int	 parse_store_modifiers(char *, struct imsg_mbox_store *,
		    const char **);
static void	 copy_move_dispatch(struct session *, const char *, char *, int,
		    int);
static int	 append_range_token(char *, size_t, size_t *, int *, uint32_t,
		    uint32_t, int *);

void
cmd_idle(struct session *s, const char *tag, char *args)
{
	s->idling = 1;
	session_write(s, "+ idling\r\n", 10);

	if (s->state == SESSION_SELECTED) {
		(void)session_request_idle_refresh(s);
		session_idle_poll_arm(s);
	}

}

/*
 * CLOSE is a silent EXPUNGE.
 */
void
cmd_close(struct session *s, const char *tag, char *args)
{
	session_request_expunge(s, tag, 1, 0, NULL, 0);
}

void
cmd_unselect(struct session *s, const char *tag, char *args)
{
	s->state = SESSION_AUTHENTICATED;
	session_reply(s, tag, "OK", "UNSELECT completed");
}

void
cmd_expunge(struct session *s, const char *tag, char *args)
{
	session_request_expunge(s, tag, 0, 0, NULL, 0);
}

int
parse_store_flags(char *flagspec, uint32_t *sysflags_out, char *keywords_out,
    size_t keywords_out_size, const char **errmsg)
{
	uint32_t	 sysflags = 0;
	size_t		 len;
	char		*p, *tok;
	int		 first = 1;

	*sysflags_out = 0;
	keywords_out[0] = '\0';

	if (flagspec == NULL || *flagspec == '\0') {
		*errmsg = "missing flag list";
		return (-1);
	}

	p = flagspec;
	len = strlen(p);
	if (len >= 2 && p[0] == '(' && p[len - 1] == ')') {
		p[len - 1] = '\0';
		p++;
	}
	/* An empty flag list is valid. */
	if (*p == '\0')
		return (0);

	while ((tok = strsep(&p, " ")) != NULL) {
		if (*tok == '\0') {
			*errmsg = "extra space";
			return (-1);
		}
		if (tok[0] == '\\') {
			if (strcasecmp(tok, "\\Answered") == 0)
				sysflags |= MBOX_FLAG_ANSWERED;
			else if (strcasecmp(tok, "\\Flagged") == 0)
				sysflags |= MBOX_FLAG_FLAGGED;
			else if (strcasecmp(tok, "\\Deleted") == 0)
				sysflags |= MBOX_FLAG_DELETED;
			else if (strcasecmp(tok, "\\Seen") == 0)
				sysflags |= MBOX_FLAG_SEEN;
			else if (strcasecmp(tok, "\\Draft") == 0)
				sysflags |= MBOX_FLAG_DRAFT;
			else if (strcasecmp(tok, "\\Recent") == 0) {
				*errmsg = "\\Recent cannot be set";
				return (PARSE_NO);
			} else {
				*errmsg = "unsupported system flag";
				return (PARSE_NO);
			}
			continue;
		}

		if (strchr(tok, ':') != NULL || strchr(tok, ',') != NULL) {
			*errmsg = "keyword contains ':' or ',', not "
			    "representable in this server's index format";
			return (PARSE_NO);
		}

		/* No cap in the RFC, so check, not truncate. */
		if (!first) {
			if (strlcat(keywords_out, ",", keywords_out_size) >=
			    keywords_out_size) {
				*errmsg = "keyword list too long";
				return (PARSE_NO);
			}
		}
		if (strlcat(keywords_out, tok, keywords_out_size) >=
		    keywords_out_size) {
			*errmsg = "keyword list too long";
			return (PARSE_NO);
		}
		first = 0;
	}

	*sysflags_out = sysflags;
	return (0);
}

/*
 * An UNCHANGEDSINCE of 0 is legal.
 */
static int
parse_store_modifiers(char *modspec, struct imsg_mbox_store *req,
    const char **errmsg)
{
	const char	*valtok, *errstr;
	size_t		 len;
	char		*p, *tok;

	len = strlen(modspec);
	if (len < 2 || modspec[0] != '(' || modspec[len - 1] != ')') {
		*errmsg = "malformed store-modifier list";
		return (-1);
	}
	modspec[len - 1] = '\0';
	p = modspec + 1;
	if (*p == '\0') {
		*errmsg = "empty store-modifier list";
		return (-1);
	}

	while ((tok = strsep(&p, " ")) != NULL) {
		if (*tok == '\0') {
			*errmsg = "extra space";
			return (-1);
		}
		if (strcasecmp(tok, "UNCHANGEDSINCE") == 0) {
			valtok = strsep(&p, " ");
			if (valtok == NULL) {
				*errmsg = "UNCHANGEDSINCE requires a "
				    "mod-sequence value";
				return (-1);
			}
			if (*valtok == '\0') {
				*errmsg = "extra space";
				return (-1);
			}
			if (*valtok < '0' || *valtok > '9') {
				*errmsg = "invalid UNCHANGEDSINCE mod-sequence";
				return (-1);
			}
			req->unchangedsince = strtonum(valtok, 0, MODSEQ_MAX,
			    &errstr);
			if (errstr != NULL) {
				*errmsg = "invalid UNCHANGEDSINCE mod-sequence";
				return (-1);
			}
			req->has_unchangedsince = 1;
		} else {
			*errmsg = "unrecognized store modifier";
			return (-1);
		}
	}

	return (0);
}

/*
 * Store modifiers come before the flags.
 */
void
cmd_store_cmd(struct session *s, const char *tag, char *args)
{
	store_do(s, tag, args, 0);
}

static void
store_do(struct session *s, const char *tag, char *args, int by_uid)
{
	struct imsg_mbox_store	 req;
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	const char		*errmsg;
	uint32_t		 nranges, sysflags;
	char			*seqtok, *modetok, *flagspec, *p;
	char			*modspec = NULL;
	char			 keywords[MBOX_FLAGS_MAX];
	int			 mode, silent, rc;

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "STORE requires a sequence set and store-att-flags");
		return;
	}

	if (next_word(&args, &seqtok, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (*args == '\0') {
		session_reply(s, tag, "BAD", "STORE requires store-att-flags");
		return;
	}

	if (*args == '(') {
		if ((p = match_paren(args)) == NULL) {
			session_reply(s, tag, "BAD",
			    "unterminated store-modifier list");
			return;
		}
		modspec = args;
		p++;
		if (*p == '\0') {
			session_reply(s, tag, "BAD",
			    "STORE requires store-att-flags");
			return;
		}
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		p[-1] = '\0';
		args = p;
	}

	if (next_word(&args, &modetok, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (*args == '\0') {
		session_reply(s, tag, "BAD", "STORE requires a flag list");
		return;
	}
	flagspec = args;

	if (parse_sequence_set(seqtok, ranges, &nranges, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}

	memset(&req, 0, sizeof(req));
	if (modspec != NULL) {
		if (parse_store_modifiers(modspec, &req, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
	}

	if (modetok[0] == '+') {
		mode = MBOX_STORE_ADD;
		modetok++;
	} else if (modetok[0] == '-') {
		mode = MBOX_STORE_REMOVE;
		modetok++;
	} else
		mode = MBOX_STORE_SET;

	if (strcasecmp(modetok, "FLAGS") == 0)
		silent = 0;
	else if (strcasecmp(modetok, "FLAGS.SILENT") == 0)
		silent = 1;
	else {
		session_reply(s, tag, "BAD",
		    "expected FLAGS, FLAGS.SILENT, +FLAGS, +FLAGS.SILENT, "
		    "-FLAGS, or -FLAGS.SILENT");
		return;
	}

	rc = parse_store_flags(flagspec, &sysflags, keywords, sizeof(keywords),
	    &errmsg);
	if (rc == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (rc == PARSE_NO) {
		session_reply(s, tag, "NO", errmsg);
		return;
	}

	if (s->mbox_readonly) {
		session_reply(s, tag, "NO", "[CANNOT] mailbox is read-only");
		return;
	}

	req.nranges = nranges;
	req.mode = mode;
	req.silent = silent;
	req.sysflags = sysflags;
	req.by_uid = by_uid;
	strlcpy(req.keywords, keywords, sizeof(req.keywords));

	if (req.has_unchangedsince)
		session_condstore_enable(s);

	s->cmd.cmd_by_uid = by_uid;
	s->state = SESSION_STORING;

	if (send_mbox_request(s, IMSG_MBOX_STORE, "IMSG_MBOX_STORE", &req,
	    sizeof(req), ranges, nranges, sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
		return;
	}

}

static void
copy_move_dispatch(struct session *s, const char *tag, char *args,
    int by_uid, int is_move)
{
	struct imsg_mbox_copy	 req;
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	const char		*errmsg;
	const char		*cmdname;
	uint32_t		 nranges;
	char			 mailbox[MBOX_NAME_MAX], text[64];
	char			*seqtok, *p;

	cmdname = is_move ?
	    (by_uid ? "UID MOVE" : "MOVE") : (by_uid ? "UID COPY" : "COPY");
	if (args == NULL) {
		snprintf(text, sizeof(text),
		    "%s requires a sequence set and mailbox name", cmdname);
		session_reply(s, tag, "BAD", text);
		return;
	}

	p = args;
	if (next_word(&p, &seqtok, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (*p == '\0') {
		snprintf(text, sizeof(text), "%s requires a mailbox name",
		    cmdname);
		session_reply(s, tag, "BAD", text);
		return;
	}

	if (parse_sequence_set(seqtok, ranges, &nranges, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}

	if (parse_mailbox_name(&p, mailbox, sizeof(mailbox), &errmsg) == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	if (*p != '\0') {
		session_reply(s, tag, "BAD", "trailing garbage after "
		    "mailbox name");
		return;
	}

	if (!listener_check_utf8(s, tag, mailbox))
		return;
	/* A refused name is NO, not BAD. */
	if (!mailbox_name_is_inbox(mailbox) &&
	    !listener_mailbox_name_valid(mailbox)) {
		session_reply(s, tag, "NO", "[CANNOT] invalid mailbox name");
		return;
	}

	if (is_move && s->mbox_readonly) {
		/* MOVE removes from the source, and COPY does not. */
		session_reply(s, tag, "NO", "[CANNOT] mailbox is read-only");
		return;
	}

	memset(&req, 0, sizeof(req));
	req.by_uid = by_uid;
	req.nranges = nranges;
	strlcpy(req.destname, mailbox, sizeof(req.destname));
	s->cmd.cmd_by_uid = by_uid;
	s->cmd.cmd_is_move = is_move;
	s->state = SESSION_COPYING;

	if (send_mbox_request(s, is_move ? IMSG_MBOX_MOVE : IMSG_MBOX_COPY,
	    is_move ? "IMSG_MBOX_MOVE" : "IMSG_MBOX_COPY", &req, sizeof(req),
	    ranges, nranges, sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
		return;
	}

}

void
cmd_copy(struct session *s, const char *tag, char *args)
{
	copy_move_dispatch(s, tag, args, 0, 0);
}

void
cmd_move(struct session *s, const char *tag, char *args)
{
	copy_move_dispatch(s, tag, args, 0, 1);
}

void
cmd_uid(struct session *s, const char *tag, char *args)
{
	const char	*errmsg;
	char		*sub, *subargs;

	if (args == NULL) {
		session_reply(s, tag, "BAD", "UID requires a sub-command");
		return;
	}

	if (next_word(&args, &sub, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	subargs = *args != '\0' ? args : NULL;

	if (strcasecmp(sub, "FETCH") == 0) {
		fetch_dispatch(s, tag, subargs, 1);
		return;
	}
	if (strcasecmp(sub, "STORE") == 0) {
		store_do(s, tag, subargs, 1);
		return;
	}
	if (strcasecmp(sub, "SEARCH") == 0) {
		search_dispatch(s, tag, subargs, 1);
		return;
	}
	if (strcasecmp(sub, "EXPUNGE") == 0) {
		uid_expunge_dispatch(s, tag, subargs);
		return;
	}
	if (strcasecmp(sub, "COPY") == 0) {
		copy_move_dispatch(s, tag, subargs, 1, 0);
		return;
	}
	if (strcasecmp(sub, "MOVE") == 0) {
		copy_move_dispatch(s, tag, subargs, 1, 1);
		return;
	}

	session_reply(s, tag, "BAD", "UID sub-command must be COPY, "
	    "EXPUNGE, FETCH, MOVE, SEARCH, or STORE");
}

/*
 * EXPUNGE, or VANISHED once QRESYNC is enabled.
 */
void
session_send_expunge_response(struct session *s,
    const struct imsg_mbox_expunged *ex)
{
	char	buf[32];

	if (s->qresync_enabled)
		snprintf(buf, sizeof(buf), "VANISHED %u", ex->uid);
	else
		snprintf(buf, sizeof(buf), "%u EXPUNGE", ex->seqno);
	session_untagged(s, buf);
}

void
session_handle_fetch_vanished(struct session *s,
    const struct imsg_mbox_select_vanished *v)
{
	char	buf[64];

	if (v->uid_lo == v->uid_hi)
		snprintf(buf, sizeof(buf), "VANISHED (EARLIER) %u", v->uid_lo);
	else
		snprintf(buf, sizeof(buf), "VANISHED (EARLIER) %u:%u",
		    v->uid_lo, v->uid_hi);
	session_untagged(s, buf);
}

/*
 * Here '*' is always a sequence number.
 */
static void
session_request_expunge(struct session *s, const char *tag, int is_close,
    int by_uid, const struct seq_range *ranges, uint32_t nranges)
{
	struct imsg_mbox_expunge	 req;

	if (s->mbox_readonly) {
		if (is_close) {
			/* Read-only, so deselect without expunging. */
			s->state = SESSION_AUTHENTICATED;
			session_reply(s, tag, "OK", "CLOSE completed");
			return;
		}
		session_reply(s, tag, "NO", "[CANNOT] mailbox is read-only");
		return;
	}

	memset(&req, 0, sizeof(req));
	req.silent = is_close;
	req.by_uid = by_uid;
	req.nranges = nranges;	/* 0 for EXPUNGE and CLOSE. */

	s->cmd.close_after_expunge = is_close;
	s->cmd.cmd_by_uid = by_uid;
	s->state = SESSION_EXPUNGING;

	if (send_mbox_request(s, IMSG_MBOX_EXPUNGE,
	    "IMSG_MBOX_EXPUNGE", &req, sizeof(req), ranges, nranges,
	    sizeof(struct seq_range)) == -1) {
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		s->state = SESSION_SELECTED;
		return;
	}

}

static void
uid_expunge_dispatch(struct session *s, const char *tag, const char *args)
{
	struct seq_range	 ranges[SEQSET_MAX_RANGES];
	const char		*errmsg;
	uint32_t		 nranges;

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "UID EXPUNGE requires a sequence set of UIDs");
		return;
	}
	if (parse_sequence_set(args, ranges, &nranges, &errmsg) == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}

	session_request_expunge(s, tag, 0, 1, ranges, nranges);
}

void
session_handle_store_modified(struct session *s,
    struct imsg_mbox_store_modified *m)
{
	uint32_t	 newcap, *n;

	if (s->cmd.store_modified_alloc_failed)
		return;

	if (s->cmd.store_modified_n == s->cmd.store_modified_cap) {
		newcap = s->cmd.store_modified_cap ?
		    s->cmd.store_modified_cap * 2 : 16;

		n = reallocarray(s->cmd.store_modified, newcap, sizeof(*n));
		if (n == NULL) {
			log_warn("session %u: realloc STORE MODIFIED array",
			    s->id);
			s->cmd.store_modified_alloc_failed = 1;
			return;
		}
		s->cmd.store_modified = n;
		s->cmd.store_modified_cap = newcap;
	}

	s->cmd.store_modified[s->cmd.store_modified_n++] =
	    s->cmd.cmd_by_uid ? m->uid : m->seqno;
}

/*
 * Append "lo" or "lo:hi" after a comma.  Return -1 if it would not fit.
 */
static int
append_range_token(char *buf, size_t bufsize, size_t *written, int *first,
    uint32_t lo, uint32_t hi, int *truncated)
{
	char	tok[24];
	int	toklen;

	if (lo == hi)
		toklen = snprintf(tok, sizeof(tok), "%u", lo);
	else
		toklen = snprintf(tok, sizeof(tok), "%u:%u", lo, hi);
	if (toklen < 0)
		return (-1);

	if (*written + (size_t)toklen + (*first ? 0 : 1) >= bufsize) {
		*truncated = 1;
		return (-1);
	}

	if (!*first)
		buf[(*written)++] = ',';
	memcpy(buf + *written, tok, (size_t)toklen);
	*written += (size_t)toklen;
	buf[*written] = '\0';
	*first = 0;
	return (0);
}

/*
 * The input must be sorted.
 */
size_t
format_seq_list(char *buf, size_t bufsize, const uint32_t *nums, uint32_t n,
    int *truncated)
{
	uint32_t	i = 0, start, end, j;
	size_t		written = 0;
	int		first = 1;

	*truncated = 0;
	buf[0] = '\0';

	while (i < n) {
		start = nums[i];
		end = start;
		j = i + 1;

		while (j < n && nums[j] == end + 1) {
			end = nums[j];
			j++;
		}

		if (append_range_token(buf, bufsize, &written, &first, start,
		    end, truncated) == -1)
			break;
		i = j;
	}

	return (written);
}

/*
 * The ranges must already be compacted.
 */
size_t
format_range_list(char *buf, size_t bufsize,
    const struct vanished_range *ranges,
    uint32_t n, int *truncated)
{
	uint32_t	i;
	size_t		written = 0;
	int		first = 1;

	*truncated = 0;
	buf[0] = '\0';

	for (i = 0; i < n; i++) {
		if (append_range_token(buf, bufsize, &written, &first,
		    ranges[i].lo, ranges[i].hi, truncated) == -1)
			break;
	}

	return (written);
}

#define COPYUID_PER_ENTRY	11
#define COPYUID_WRAPPER_MAX	160

void
session_finish_copy_or_move(struct session *s,
    const struct imsg_mbox_result *res)
{
	const char	*cmdname;
	uint32_t	 i;
	size_t		 listsize, textsize;
	char		 reply[48], *srcbuf, *destbuf, *text, fallback[64];
	int		 truncated, n, sent;

	cmdname = s->cmd.cmd_is_move ?
	    (s->cmd.cmd_by_uid ? "UID MOVE" : "MOVE") :
	    (s->cmd.cmd_by_uid ? "UID COPY" : "COPY");
	s->state = SESSION_SELECTED;

	if (res->error != MBOX_OP_OK || s->cmd.copy_alloc_failed) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    s->cmd.copy_alloc_failed ?
		    mbox_error_text(MBOX_OP_ERR_GENERIC, cmdname, reply,
		    sizeof(reply)) :
		    res->error == MBOX_OP_ERR_NO_SUCH_MAILBOX ?
		    "[TRYCREATE] no such mailbox" :
		    mbox_error_text(res->error, cmdname, reply, sizeof(reply)));
		return;
	}

	s->mbox_highestmodseq = res->highestmodseq;

	if (s->cmd.copy_n > 0) {
		srcbuf = NULL;
		destbuf = NULL;
		text = NULL;
		sent = 0;

		listsize = (size_t)s->cmd.copy_n * COPYUID_PER_ENTRY + 1;
		textsize = 2 * listsize + COPYUID_WRAPPER_MAX;

		if ((srcbuf = malloc(listsize)) != NULL &&
		    (destbuf = malloc(listsize)) != NULL &&
		    (text = malloc(textsize)) != NULL) {
			format_seq_list(srcbuf, listsize, s->cmd.copy_src_uids,
			    s->cmd.copy_n, &truncated);
			if (truncated)
				log_warnx("session %u: COPYUID source list "
				    "truncated", s->id);
			format_seq_list(destbuf, listsize,
			    s->cmd.copy_dest_uids, s->cmd.copy_n, &truncated);
			if (truncated)
				log_warnx("session %u: COPYUID dest list "
				    "truncated", s->id);

			/* MOVE sends COPYUID untagged, before the EXPUNGEs. */
			if (s->cmd.cmd_is_move)
				n = snprintf(text, textsize,
				    "* OK [COPYUID %u %s %s]\r\n",
				    res->uidvalidity, srcbuf, destbuf);
			else
				n = snprintf(text, textsize,
				    "%s OK [COPYUID %u %s %s] %s completed\r\n",
				    s->cmd.pending_tag, res->uidvalidity,
				    srcbuf, destbuf, cmdname);
			if (n < 0 || (size_t)n >= textsize)
				log_warnx("session %u: COPYUID response text "
				    "truncated", s->id);
			else {
				session_write(s, text, (size_t)n);
				sent = 1;
			}
		} else
			log_warn("session %u: malloc COPYUID response", s->id);

		free(srcbuf);
		free(destbuf);
		free(text);

		if (s->cmd.cmd_is_move) {
			for (i = 0; i < s->cmd.move_expunged_n; i++)
				session_send_expunge_response(s,
				    &s->cmd.move_expunged[i]);
		} else if (sent)
			return;
	}

	/* Omit COPYUID, only a SHOULD, rather than truncate it. */
	if (s->cmd.cmd_is_move && s->condstore_enabled && res->count > 0)
		/* RFC 6851 section 4.4. */
		snprintf(fallback, sizeof(fallback),
		    "[HIGHESTMODSEQ %llu] %s completed",
		    (unsigned long long)res->highestmodseq, cmdname);
	else
		snprintf(fallback, sizeof(fallback), "%s completed", cmdname);
	session_reply(s, s->cmd.pending_tag, "OK", fallback);
}
