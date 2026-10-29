#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>

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

static int	 kw_list_contains(const char *, const char *);
static int	 append_kw_token(char *, size_t, int *, const char *);
static int	 search_eval_leaf(const struct search_node *,
		    const struct search_msg_ctx *);
static int	 search_eval(const struct search_node *, uint32_t,
		    const struct search_msg_ctx *, const uint32_t *,
		    const char *);
static int	 search_walk_ask(struct store_session *);
static void	 search_walk_match(struct store_session *, uint32_t);
static void	 search_walk_step(struct store_session *);
static void	 search_walk_finish(struct store_session *, int);
static void	 search_save_match(struct store_search_walk *, uint32_t,
		    uint32_t);
static int	 search_save_finish(struct store_session *, int);
static void	 search_walk_yield(int, short, void *);

static int
kw_list_contains(const char *list, const char *kw)
{
	const char	*tok;
	char		 tmp[MBOX_FLAGS_MAX];
	char		*p;
	int		 empty = 0, found = 0;

	if (strlcpy(tmp, list, sizeof(tmp)) >= sizeof(tmp)) {
		log_warnx("keyword list too long, no match");
		return (0);
	}
	p = (tmp[0] != '\0') ? tmp : NULL;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (*tok == '\0') {
			empty = 1;
			continue;
		}
		if (strcasecmp(tok, kw) == 0)
			found = 1;
	}
	if (empty)
		log_warnx("empty keyword in index, skipped");
	return (found);
}

static int
append_kw_token(char *out, size_t outsize, int *firstp, const char *tok)
{
	if (!*firstp && strlcat(out, ",", outsize) >= outsize) {
		log_warnx("merge_keywords: keyword set does not fit in %zu "
		    "bytes", outsize);
		return (0);
	}
	if (strlcat(out, tok, outsize) >= outsize) {
		log_warnx("merge_keywords: keyword set does not fit in %zu "
		    "bytes", outsize);
		return (0);
	}
	*firstp = 0;
	return (1);
}

int
merge_keywords(int mode, const char *old_kws, const char *new_kws,
    char *out, size_t outsize)
{
	const char	*tok;
	char		 tmp[MBOX_FLAGS_MAX];
	char		*p;
	int		 first = 1, empty = 0;

	out[0] = '\0';

	if (mode == MBOX_STORE_REMOVE) {
		if (strlcpy(tmp, old_kws, sizeof(tmp)) >= sizeof(tmp)) {
			log_warnx("STORE: old keyword list too long");
			return (-1);
		}
		p = (tmp[0] != '\0') ? tmp : NULL;
		while ((tok = strsep(&p, ",")) != NULL) {
			if (*tok == '\0') {
				empty = 1;
				continue;
			}
			if (kw_list_contains(new_kws, tok))
				continue;
			if (!append_kw_token(out, outsize, &first, tok))
				return (-1);
		}
		if (empty)
			log_warnx("empty keyword in index, skipped");
		return (0);
	}

	if (mode == MBOX_STORE_ADD) {
		if (strlcpy(tmp, old_kws, sizeof(tmp)) >= sizeof(tmp)) {
			log_warnx("STORE: old keyword list too long");
			return (-1);
		}
		p = (tmp[0] != '\0') ? tmp : NULL;
		while ((tok = strsep(&p, ",")) != NULL) {
			if (*tok == '\0') {
				empty = 1;
				continue;
			}
			if (!append_kw_token(out, outsize, &first, tok))
				return (-1);
		}
		if (empty)
			log_warnx("empty keyword in index, skipped");
	}

	if (strlcpy(tmp, new_kws, sizeof(tmp)) >= sizeof(tmp)) {
		log_warnx("STORE: new keyword list too long");
		return (-1);
	}
	p = (tmp[0] != '\0') ? tmp : NULL;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (*tok == '\0' || kw_list_contains(out, tok))
			continue;
		if (!append_kw_token(out, outsize, &first, tok))
			return (-1);
	}
	return (0);
}

/* A content key's value before the parser has answered. */
#define SEARCH_UNKNOWN		2

/* Messages a SEARCH examines before yielding. */
#define SEARCH_YIELD_MESSAGES	1000

static int
search_eval_leaf(const struct search_node *n, const struct search_msg_ctx *m)
{
	switch (n->op) {
	case SEARCH_OP_ALL:
		return (1);
	case SEARCH_OP_ANSWERED:
		return ((m->sysflags & MBOX_FLAG_ANSWERED) != 0);
	case SEARCH_OP_UNANSWERED:
		return ((m->sysflags & MBOX_FLAG_ANSWERED) == 0);
	case SEARCH_OP_DELETED:
		return ((m->sysflags & MBOX_FLAG_DELETED) != 0);
	case SEARCH_OP_UNDELETED:
		return ((m->sysflags & MBOX_FLAG_DELETED) == 0);
	case SEARCH_OP_DRAFT:
		return ((m->sysflags & MBOX_FLAG_DRAFT) != 0);
	case SEARCH_OP_UNDRAFT:
		return ((m->sysflags & MBOX_FLAG_DRAFT) == 0);
	case SEARCH_OP_FLAGGED:
		return ((m->sysflags & MBOX_FLAG_FLAGGED) != 0);
	case SEARCH_OP_UNFLAGGED:
		return ((m->sysflags & MBOX_FLAG_FLAGGED) == 0);
	case SEARCH_OP_SEEN:
		return ((m->sysflags & MBOX_FLAG_SEEN) != 0);
	case SEARCH_OP_UNSEEN:
		return ((m->sysflags & MBOX_FLAG_SEEN) == 0);
	case SEARCH_OP_KEYWORD:
		return (kw_list_contains(m->keywords, n->keyword));
	case SEARCH_OP_UNKEYWORD:
		return (!kw_list_contains(m->keywords, n->keyword));
	case SEARCH_OP_BEFORE:
		return (m->internaldate < n->num);
	case SEARCH_OP_ON:
		return (m->internaldate >= n->num &&
		    m->internaldate < n->num + 86400);
	case SEARCH_OP_SINCE:
		return (m->internaldate >= n->num);
	case SEARCH_OP_LARGER:
		return ((int64_t)m->size > n->num);
	case SEARCH_OP_SMALLER:
		return ((int64_t)m->size < n->num);
	case SEARCH_OP_SEQSET:
		return (m->seqno >= n->seq_lo && m->seqno <= n->seq_hi);
	case SEARCH_OP_UIDSET:
		return (m->uid >= n->seq_lo && m->uid <= n->seq_hi);
	case SEARCH_OP_MODSEQ:
		return (m->modseq >= (uint64_t)n->num);
	case SEARCH_OP_SAVED:
		return (seqset_contains(m->saved, m->nsaved, m->uid));
	default:
		return (0);
	}
}

int
search_op_content(int op)
{
	return (op == SEARCH_OP_SUBJECT || op == SEARCH_OP_HEADER ||
	    op == SEARCH_OP_SENTBEFORE || op == SEARCH_OP_SENTON ||
	    op == SEARCH_OP_SENTSINCE || op == SEARCH_OP_FROM ||
	    op == SEARCH_OP_TO || op == SEARCH_OP_CC || op == SEARCH_OP_BCC ||
	    op == SEARCH_OP_BODY || op == SEARCH_OP_TEXT);
}

static int
search_eval(const struct search_node *nodes, uint32_t nnodes,
    const struct search_msg_ctx *m, const uint32_t *leafidx,
    const char *bits)
{
	const struct search_node	*n;
	uint32_t			sp = 0, i;
	int				stack[SEARCH_PROGRAM_MAX_NODES];
	int				a, b;

	for (i = 0; i < nnodes; i++) {
		n = &nodes[i];

		switch (n->op) {
		case SEARCH_OP_AND:
			if (sp < 2)
				return (0);
			b = stack[--sp];
			a = stack[sp - 1];
			stack[sp - 1] = (a == 0 || b == 0) ? 0 :
			    (a == 1 && b == 1) ? 1 : SEARCH_UNKNOWN;
			break;
		case SEARCH_OP_OR:
			if (sp < 2)
				return (0);
			b = stack[--sp];
			a = stack[sp - 1];
			stack[sp - 1] = (a == 1 || b == 1) ? 1 :
			    (a == 0 && b == 0) ? 0 : SEARCH_UNKNOWN;
			break;
		case SEARCH_OP_NOT:
			if (sp < 1)
				return (0);
			if (stack[sp - 1] != SEARCH_UNKNOWN)
				stack[sp - 1] = !stack[sp - 1];
			break;
		default:
			if (sp >= SEARCH_PROGRAM_MAX_NODES)
				return (0);
			if (!search_op_content(n->op))
				stack[sp++] = search_eval_leaf(n, m);
			else if (bits == NULL)
				stack[sp++] = SEARCH_UNKNOWN;
			else
				stack[sp++] = bits[leafidx[i]];
			break;
		}
	}

	return (sp == 1 ? stack[0] : 0);
}

int
handle_mbox_search(struct imsg_mbox_search *req, struct search_node *nodes,
    uint32_t nnodes, struct store_session *ss)
{
	struct store_search_walk	*sw = &ss->search;
	struct imsg_parser_leaf		 leaf;
	struct search_node		*n;
	struct index_lock		 il = INDEX_LOCK_INIT;
	struct seq_range		 in, out;
	uint32_t			 max_uid, i, nout, max;
	int				 locked, by_uid;

	/* Lock first, so a busy return changes nothing. */
	locked = index_lock_acquire(ss->mailbox_dir_fd, &il, LOCK_SH | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		return (1);

	if (sw->active) {
		log_warnx("session %u: SEARCH during a SEARCH, earlier walk "
		    "abandoned", ss->id);
		search_walk_abort(ss);
	}
	memset(sw, 0, sizeof(*sw));
	sw->opts = req->return_opts;
	evtimer_set(&sw->yield_ev, search_walk_yield, ss);

	if (locked == INDEX_LOCK_ERR) {
		search_walk_finish(ss, 0);
		return (0);
	}
	if (index_load(il.fd, &sw->idx) == -1) {
		index_lock_release(&il);
		search_walk_finish(ss, 0);
		return (0);
	}
	index_lock_release(&il);

	if (nnodes > 0)
		memcpy(sw->nodes, nodes, nnodes * sizeof(*nodes));
	sw->nnodes = nnodes;

	max_uid = index_max_uid(&sw->idx);
	(void)view_sync(ss, &sw->idx, 0);

	for (i = 0; i < nnodes; i++) {
		n = &sw->nodes[i];

		if (search_op_content(n->op)) {
			memset(&leaf, 0, sizeof(leaf));
			leaf.op = n->op;
			leaf.str_off = n->str_off;
			leaf.str_len = n->str_len;
			leaf.name_off = n->name_off;
			leaf.name_len = n->name_len;
			leaf.num = n->num;
			memcpy(sw->extra + sw->nleaves * sizeof(leaf), &leaf,
			    sizeof(leaf));
			sw->leafidx[i] = sw->nleaves++;
			continue;
		}
		if (n->op != SEARCH_OP_SEQSET && n->op != SEARCH_OP_UIDSET)
			continue;

		max = (n->op == SEARCH_OP_SEQSET) ?
		    (uint32_t)sw->idx.nlines : max_uid;
		in.lo = n->seq_lo;
		in.hi = n->seq_hi;
		in.lo_is_star = n->lo_is_star;
		in.hi_is_star = n->hi_is_star;

		by_uid = n->op == SEARCH_OP_UIDSET;
		view_resolve(ss, &in, 1, &out, &nout, &by_uid);
		if (n->op == SEARCH_OP_SEQSET && by_uid) {
			n->op = SEARCH_OP_UIDSET;
			n->seq_lo = nout > 0 ? out.lo : 0;
			n->seq_hi = nout > 0 ? out.hi : 0;
			n->lo_is_star = n->hi_is_star = 0;
			continue;
		}
		(void)seqset_resolve(&in, 1, max, n->op == SEARCH_OP_SEQSET,
		    &out);
		n->seq_lo = out.lo;
		n->seq_hi = out.hi;
		n->lo_is_star = n->hi_is_star = 0;
	}
	/* Bounded by the pool in store.c. */
	sw->poollen = req->poollen;
	sw->extralen = sw->nleaves * sizeof(leaf);
	memcpy(sw->extra + sw->extralen, req->pool, req->poollen);
	sw->extralen += req->poollen;

	sw->next = 1;
	sw->active = 1;
	search_walk_step(ss);
	return (0);
}

static int
search_walk_ask(struct store_session *ss)
{
	struct store_search_walk	*sw = &ss->search;
	struct imsg_parser_req		 preq;
	struct parser_ask		 ask;
	int				 mfd, ready, rc;

	if ((ready = parser_ready()) == 0) {
		sw->wait_parser = 1;
		return (0);
	}
	if (ready == -1) {
		log_warnx("session %u: SEARCH needs the parser-worker and "
		    "none can be had", ss->id);
		return (-1);
	}
	if ((mfd = open_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
	    sw->rec.basename)) == -1) {
		log_warnx("session %u: message %s: open failed, SEARCH cannot "
		    "check it", ss->id, sw->rec.basename);
		return (-1);
	}
	memset(&preq, 0, sizeof(preq));
	preq.nleaves = sw->nleaves;
	preq.poollen = sw->poollen;
	memset(&ask, 0, sizeof(ask));
	ask.type = IMSG_PARSER_SEARCH;
	ask.label = "SEARCH";
	ask.fd = mfd;
	ask.basename = sw->rec.basename;
	ask.req = &preq;
	ask.extra = sw->extra;
	ask.extralen = sw->extralen;
	ask.maxlen = sw->nleaves;
	rc = parser_send(ss, &ask);
	close(mfd);
	if (rc == -1) {
		log_warnx("session %u: message %s could not be checked, "
		    "SEARCH fails", ss->id, sw->rec.basename);
		return (-1);
	}
	sw->wait_reply = 1;
	return (0);
}

static void
search_walk_match(struct store_session *ss, uint32_t line)
{
	struct imsg_mbox_search_match	 match;
	struct store_search_walk	*sw = &ss->search;

	if (sw->opts & SEARCH_RETURN_SAVE)
		search_save_match(sw, line, sw->msg.uid);
	memset(&match, 0, sizeof(match));
	match.seqno = sw->msg.seqno;
	match.uid = sw->msg.uid;
	match.modseq = sw->msg.modseq;
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_SEARCH_MATCH, 0, 0, -1,
	    &match, sizeof(match)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_SEARCH_MATCH",
		    ss->id);
	else
		sw->sent++;
}

static void
search_walk_step(struct store_session *ss)
{
	struct store_search_walk	*sw = &ss->search;
	struct search_msg_ctx		*m = &ss->search.msg;
	struct index_rec		*rec = &ss->search.rec;
	struct timeval			 tv;
	const char			*letters;
	char				 suffix[64];
	off_t				 size;
	uint32_t			 i;
	int				 r;

	for (i = sw->next; i <= (uint32_t)sw->idx.nlines; i++) {
		size = 0;

		if (++sw->walked > SEARCH_YIELD_MESSAGES) {
			sw->walked = 0;
			sw->next = i;
			timerclear(&tv);
			evtimer_add(&sw->yield_ev, &tv);
			return;
		}
		if (index_parse_line(sw->idx.lines[i - 1], rec) == -1)
			continue;

		memset(m, 0, sizeof(*m));
		m->seqno = view_seqno(ss, rec->uid, i);
		m->uid = rec->uid;
		m->modseq = rec->modseq;
		m->saved = ss->saved;
		m->nsaved = ss->nsaved;

		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec->basename, &size, suffix, sizeof(suffix)) == -1) {
			log_warnx("session %u: message %s (uid %u) indexed "
			    "but missing on disk, skipped", ss->id,
			    rec->basename, m->uid);
			continue;
		}

		letters = strstr(suffix, "2,");
		letters = (letters != NULL) ? letters + 2 : "";
		m->sysflags = letters_to_sysflags(letters);
		m->keywords = rec->keywords;
		m->internaldate = parse_maildir_timestamp(rec->basename);
		m->size = (uint64_t)size;

		r = search_eval(sw->nodes, sw->nnodes, m, sw->leafidx, NULL);
		if (r == SEARCH_UNKNOWN) {
			sw->next = i;
			if (search_walk_ask(ss) == -1)
				search_walk_finish(ss, 0);
			return;
		}
		if (r == 1)
			search_walk_match(ss, i);
	}
	search_walk_finish(ss, 1);
}

static void
search_walk_finish(struct store_session *ss, int ok)
{
	struct store_search_walk	*sw = &ss->search;
	struct imsg_mbox_result		 result;

	index_free(&sw->idx);
	cur_snapshot_discard(&ss->cur_snap);

	memset(&result, 0, sizeof(result));
	result.error = !search_save_finish(ss, ok) ? MBOX_OP_ERR_NOTSAVED :
	    ok ? MBOX_OP_OK : MBOX_OP_ERR_GENERIC;
	result.count = sw->sent;
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
	sw->active = 0;
}

/*
 * Matches on adjacent index lines share one range.
 */
static void
search_save_match(struct store_search_walk *sw, uint32_t line, uint32_t uid)
{
	if (sw->sv_first == 0)
		sw->sv_first = uid;
	sw->sv_last = uid;
	if (sw->nsv > 0 && sw->sv_line + 1 == line)
		sw->sv[sw->nsv - 1].hi = uid;
	else if (sw->nsv < SEQSET_MAX_RANGES) {
		memset(&sw->sv[sw->nsv], 0, sizeof(sw->sv[0]));
		sw->sv[sw->nsv].lo = sw->sv[sw->nsv].hi = uid;
		sw->nsv++;
	} else
		sw->sv_full = 1;
	sw->sv_line = line;
}

/*
 * A refused save returns 0, reported as NOTSAVED.
 */
static int
search_save_finish(struct store_session *ss, int ok)
{
	struct store_search_walk	*sw = &ss->search;
	uint32_t			 o = sw->opts, n = 0;

	if (!(o & SEARCH_RETURN_SAVE))
		return (1);
	ss->nsaved = 0;
	if (!ok)
		return (1);
	if ((o & (SEARCH_RETURN_MIN | SEARCH_RETURN_MAX)) &&
	    !(o & (SEARCH_RETURN_ALL | SEARCH_RETURN_COUNT))) {
		if (sw->sv_first == 0)
			return (1);
		memset(ss->saved, 0, 2 * sizeof(ss->saved[0]));
		if (o & SEARCH_RETURN_MIN) {
			ss->saved[n].lo = ss->saved[n].hi = sw->sv_first;
			n++;
		}
		if ((o & SEARCH_RETURN_MAX) && (n == 0 ||
		    sw->sv_last != sw->sv_first)) {
			ss->saved[n].lo = ss->saved[n].hi = sw->sv_last;
			n++;
		}
		ss->nsaved = n;
		return (1);
	}
	if (sw->sv_full)
		return (0);
	memcpy(ss->saved, sw->sv, sw->nsv * sizeof(sw->sv[0]));
	ss->nsaved = sw->nsv;
	return (1);
}

static void
search_walk_yield(int fd, short event, void *arg)
{
	struct store_session	*ss = arg;

	if (ss->search.active)
		search_walk_step(ss);
}

int
search_walk_paused(struct store_session *ss)
{
	return (ss->search.active);
}

void
search_walk_abort(struct store_session *ss)
{
	struct store_search_walk	*sw = &ss->search;

	if (!sw->active)
		return;
	parser_cancel(ss);
	evtimer_del(&sw->yield_ev);
	index_free(&sw->idx);
	sw->active = 0;
}

void
search_walk_parser(struct store_session *ss, int ok)
{
	struct store_search_walk	*sw = &ss->search;

	if (!sw->active || !sw->wait_parser)
		return;
	sw->wait_parser = 0;
	if (!ok) {
		log_warnx("session %u: no parser-worker, SEARCH fails",
		    ss->id);
		search_walk_finish(ss, 0);
		return;
	}
	search_walk_step(ss);
}

void
search_walk_parsed(struct store_session *ss, int rc,
    const struct imsg_parser_rep *rep, char *bits)
{
	struct store_search_walk	*sw = &ss->search;
	int				 r;

	sw->wait_reply = 0;
	if (rc == -1) {
		log_warnx("session %u: message %s could not be checked, "
		    "SEARCH fails", ss->id, sw->rec.basename);
		search_walk_finish(ss, 0);
		return;
	}
	r = search_eval(sw->nodes, sw->nnodes, &sw->msg, sw->leafidx, bits);
	free(bits);
	if (r == 1)
		search_walk_match(ss, sw->next);
	sw->next++;
	search_walk_step(ss);
}
