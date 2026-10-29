#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>

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

/* Items in the order the listener takes them. */
#define FETCH_STAGE_HEADER		0
#define FETCH_STAGE_BODY		1
#define FETCH_STAGE_ENVELOPE		2
#define FETCH_STAGE_BODYSTRUCTURE	3

static void		 fetch_walk_step(struct store_session *);
static int		 fetch_walk_next(struct store_session *);
static int		 fetch_item(struct store_session *);
static void		 fetch_walk_finish(struct store_session *, int);
static const char	*fetch_cached(struct store_session *,
		    const struct index_rec *, int, int *, uint32_t *);
static void		 fetch_send_part(struct store_session *, int,
		    const char *, const void *, size_t, int, const void *,
		    uint32_t);
static int		 fetch_set_seen(struct store_session *, int);
static int		 fetch_meta(struct store_session *,
		    const struct index_rec *, uint32_t,
		    struct imsg_mbox_fetch_meta *, int *);
static int		 fetch_ask(struct store_session *,
		    const struct parser_ask *);
static void		 fetch_send_header(struct store_session *, int,
		    const char *, uint32_t);
static int		 fetch_header(struct store_session *);
static void		 fetch_send_body(struct store_session *, int, int,
		    uint64_t, uint64_t);
static int		 fetch_body(struct store_session *);
static void		 fetch_send_parsed(struct store_session *, const char *,
		    uint32_t);
static int		 fetch_parsed(struct store_session *, int);
static void		 fetch_send_meta(struct store_session *);

static void
fetch_send_part(struct store_session *ss, int imsg_type, const char *what,
    const void *meta, size_t metalen, int found, const void *buf,
    uint32_t buflen)
{
	struct iovec	 iov[2];

	iov[0].iov_base = (void *)meta;
	iov[0].iov_len = metalen;
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = found ? buflen : 0;
	if (imsg_composev(&ss->iev.ibuf, imsg_type, 0, 0, -1, iov,
	    iov[1].iov_len > 0 ? 2 : 1) == -1)
		log_warn("session %u: imsg_composev %s", ss->id, what);
	else
		ss->fetch.composed += metalen + iov[1].iov_len;
}

/*
 * BODY[] sets \Seen, through the same code as STORE.
 */
static int
fetch_set_seen(struct store_session *ss, int synced)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct imsg_mbox_store	 sreq;
	struct store_step	*steps = NULL;
	size_t			 nsteps = 0;
	uint64_t		 before = fw->idx.highestmodseq;
	int			 ok;

	memset(&sreq, 0, sizeof(sreq));
	sreq.mode = MBOX_STORE_ADD;
	sreq.sysflags = MBOX_FLAG_SEEN;
	ok = store_apply(ss, &sreq, &fw->idx, fw->resolved, fw->nresolved,
	    fw->req.by_uid, synced, fw->req.has_changedsince ?
	    &fw->req.changedsince : NULL, &steps, &nsteps);
	free(steps);
	if (!ok)
		return (-1);
	if (fw->idx.highestmodseq != before) {
		fw->seen_modseq = fw->idx.highestmodseq;
		/* The renames left the snapshot naming old files. */
		cur_snapshot_discard(&ss->cur_snap);
	}
	return (0);
}

int
handle_mbox_fetch(struct imsg_mbox_fetch *req, const struct seq_range *ranges,
    uint32_t nranges, struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct mbox_index	*idx = &fw->idx;
	struct index_lock	 il = INDEX_LOCK_INIT;
	struct seq_range	 vr[SEQSET_MAX_RANGES];
	uint32_t		 i, nvr;
	int			 locked, synced, rc, set_seen, used;

	set_seen = (req->attrs & MBOX_FETCH_SET_SEEN) != 0;
	/* Lock first, so a busy return changes nothing. */
	locked = index_lock_acquire(ss->mailbox_dir_fd, &il,
	    (set_seen ? LOCK_EX : LOCK_SH) | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		return (1);

	if (fw->active) {
		log_warnx("session %u: FETCH during a paused FETCH, earlier "
		    "walk abandoned", ss->id);
		fetch_walk_abort(ss);
	}
	memset(fw, 0, sizeof(*fw));
	fw->req = *req;
	fw->next = 1;
	fw->part_fd = -1;

	if (locked == INDEX_LOCK_ERR) {
		fetch_walk_finish(ss, 0);
		return (0);
	}
	if (index_load(il.fd, idx) == -1) {
		index_lock_release(&il);
		fetch_walk_finish(ss, 0);
		return (0);
	}
	if (!set_seen)
		index_lock_release(&il);
	pcache_check_mailbox(ss->selected_mailbox, idx->uidvalidity);

	synced = view_sync(ss, idx, req->by_uid) == 0;
	if ((rc = saved_resolve(ss, ranges, nranges, vr, &nvr,
	    &fw->req.by_uid, &used)) != 0) {
		if (set_seen)
			index_lock_release(&il);
		fw->limit = rc == -1;
		fetch_walk_finish(ss, 0);
		return (0);
	}
	fw->nresolved = seqset_resolve(vr, nvr, fw->req.by_uid ?
	    index_max_uid(idx) : (uint32_t)idx->nlines, !fw->req.by_uid,
	    fw->resolved);
	fw->max_hi = seqset_max_hi(fw->resolved, fw->nresolved);
	fw->ghost = !req->by_uid && !used &&
	    view_names_ghost(ss, idx, fw->resolved, fw->nresolved);

	if (set_seen) {
		rc = fetch_set_seen(ss, synced);
		index_lock_release(&il);
		if (rc == -1) {
			fetch_walk_finish(ss, 0);
			return (0);
		}
	}

	/* VANISHED (EARLIER) goes out first. */
	if (req->by_uid && req->want_vanished) {
		for (i = 0; i < fw->nresolved; i++)
			send_vanished_range(idx, fw->resolved[i].lo,
			    fw->resolved[i].hi, ss);
	}

	fw->active = 1;
	fetch_walk_step(ss);
	return (0);
}

/*
 * A hit still needs the file on disk.
 */
static const char *
fetch_cached(struct store_session *ss, const struct index_rec *rec,
    int item, int *have_file, uint32_t *lenp)
{
	const char	*text;
	off_t		 size;
	char		 suffix[64];

	if ((text = pcache_get(ss->selected_mailbox, ss->fetch.idx.uidvalidity,
	    rec->uid, rec->basename, item, lenp)) == NULL)
		return (NULL);
	if (*have_file == 0 && locate_message_file(&ss->cur_snap,
	    ss->mailbox_dir_fd, rec->basename, &size, suffix,
	    sizeof(suffix)) == -1)
		return (NULL);
	*have_file = 1;
	return (text);
}

static int
fetch_meta(struct store_session *ss, const struct index_rec *rec, uint32_t i,
    struct imsg_mbox_fetch_meta *meta, int *have_file)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct imsg_mbox_fetch	*req = &fw->req;
	off_t			 size = 0;
	char			 suffix[64];

	memset(meta, 0, sizeof(*meta));
	meta->seqno = view_seqno(ss, rec->uid, i);
	meta->uid = rec->uid;
	meta->modseq = rec->modseq;
	meta->seen_set = fw->seen_modseq != 0 && rec->modseq == fw->seen_modseq;

	if (meta->seen_set ||
	    (req->attrs & (MBOX_FETCH_RFC822_SIZE | MBOX_FETCH_FLAGS))) {
		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec->basename, &size, suffix, sizeof(suffix)) == -1) {
			log_warnx("session %u: message %s (uid %u) indexed but "
			    "missing on disk, skipped", ss->id,
			    rec->basename, meta->uid);
			return (-1);
		}
		*have_file = 1;
	}

	if (req->attrs & MBOX_FETCH_RFC822_SIZE)
		meta->size = (uint64_t)size;
	if ((req->attrs & MBOX_FETCH_FLAGS) || meta->seen_set)
		build_flags_string(*have_file ? suffix : "", rec->keywords,
		    meta->flags, sizeof(meta->flags));
	if (req->attrs & MBOX_FETCH_INTERNALDATE)
		meta->internaldate = parse_maildir_timestamp(rec->basename);
	return (0);
}

/*
 * Return 0 to answer the item now.  Return -1 once the parser is asked or
 * busy.
 */
static int
fetch_ask(struct store_session *ss, const struct parser_ask *ask)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	if (fw->no_parser)
		return (0);
	switch (parser_ready()) {
	case 0:
		fw->wait_parser = 1;
		return (-1);
	case -1:
		fw->no_parser = 1;
		return (0);
	default:
		break;
	}
	if (parser_send(ss, ask) == -1)
		return (0);
	fw->wait_reply = 1;
	return (-1);
}

static void
fetch_send_header(struct store_session *ss, int found, const char *buf,
    uint32_t len)
{
	struct imsg_mbox_fetch_header	 hdrmeta;

	memset(&hdrmeta, 0, sizeof(hdrmeta));
	hdrmeta.seqno = ss->fetch.meta.seqno;
	hdrmeta.uid = ss->fetch.rec.uid;
	if (found) {
		hdrmeta.found = 1;
		hdrmeta.hdrlen = len;
	}
	fetch_send_part(ss, IMSG_MBOX_FETCH_HEADER, "IMSG_MBOX_FETCH_HEADER",
	    &hdrmeta, sizeof(hdrmeta), hdrmeta.found, buf, len);
}

static int
fetch_header(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct imsg_parser_req	 preq;
	struct parser_ask	 ask;
	char			*hdrbuf = NULL;
	uint32_t		 hdrlen = 0;
	int			 mfd, rc;

	if (fw->req.attrs & MBOX_FETCH_BODY_HEADER) {
		rc = read_message_header(&ss->cur_snap, ss->mailbox_dir_fd,
		    fw->rec.basename, &hdrbuf, &hdrlen);
		fetch_send_header(ss, rc == 0, hdrbuf, hdrlen);
		free(hdrbuf);
		return (0);
	}
	if ((mfd = open_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
	    fw->rec.basename)) == -1) {
		fetch_send_header(ss, 0, NULL, 0);
		return (0);
	}
	memset(&preq, 0, sizeof(preq));
	(void)strlcpy(preq.fields, fw->req.header_fields, sizeof(preq.fields));
	preq.fields_not = fw->req.header_fields_not;
	memset(&ask, 0, sizeof(ask));
	ask.type = IMSG_PARSER_HEADER_FIELDS;
	ask.label = "HEADER.FIELDS";
	ask.fd = mfd;
	ask.basename = fw->rec.basename;
	ask.req = &preq;
	ask.maxlen = FETCH_HEADER_MAX;
	rc = fetch_ask(ss, &ask);
	close(mfd);
	if (rc == 0)
		fetch_send_header(ss, 0, NULL, 0);
	return (rc);
}

static void
fetch_send_body(struct store_session *ss, int fd, int found, uint64_t off,
    uint64_t len)
{
	struct store_fetch_walk		*fw = &ss->fetch;
	struct imsg_mbox_fetch		*req = &fw->req;
	struct imsg_mbox_fetch_body	 bodymeta;

	memset(&bodymeta, 0, sizeof(bodymeta));
	bodymeta.seqno = fw->meta.seqno;
	bodymeta.uid = fw->rec.uid;
	if (found) {
		partial_range(req->has_partial, req->partial_start,
		    req->partial_count, &off, &len);
		bodymeta.found = 1;
		bodymeta.offset = off;
		bodymeta.length = len;
	}
	if (fd != -1 && (!found || len == 0)) {
		close(fd);
		fd = -1;
	}

	/* Only a successful compose takes the descriptor. */
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_FETCH_BODY, 0, 0, fd,
	    &bodymeta, sizeof(bodymeta)) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_FETCH_BODY",
		    ss->id);
		if (fd != -1)
			close(fd);
	} else {
		fw->composed += sizeof(bodymeta);
		if (fd != -1)
			fw->fds++;
	}
}

/*
 * WHOLE wins over TEXT and PART.  Return -1 to wait, as fetch_item() does.
 */
static int
fetch_body(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct imsg_mbox_fetch	*req = &fw->req;
	struct imsg_parser_req	 preq;
	struct parser_ask	 ask;
	uint64_t		 off = 0, len = 0;
	int			 fd, fdbusy = 0;

	if (!(req->attrs & MBOX_FETCH_BODY_PART) ||
	    (req->attrs & (MBOX_FETCH_BODY_WHOLE | MBOX_FETCH_BODY_TEXT))) {
		fd = message_body_range(&ss->cur_snap, ss->mailbox_dir_fd,
		    fw->rec.basename, !(req->attrs & MBOX_FETCH_BODY_WHOLE),
		    &off, &len, &fdbusy);
		/* Out of descriptors, so retry once some are sent. */
		if (fdbusy && fw->fds > 0)
			return (-1);
		fetch_send_body(ss, fd, fd != -1, off, len);
		return (0);
	}

	memset(&preq, 0, sizeof(preq));
	preq.pathlen = parse_section_part(req->section_part, preq.path,
	    MIME_MAX_DEPTH);
	if (preq.pathlen == -1) {
		fetch_send_body(ss, -1, 0, 0, 0);
		return (0);
	}
	if ((fd = open_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
	    fw->rec.basename)) == -1) {
		if ((errno == EMFILE || errno == ENFILE) && fw->fds > 0)
			return (-1);
		fetch_send_body(ss, -1, 0, 0, 0);
		return (0);
	}
	memset(&ask, 0, sizeof(ask));
	ask.type = IMSG_PARSER_PART;
	ask.label = "BODY[<part>]";
	ask.fd = fd;
	ask.basename = fw->rec.basename;
	ask.req = &preq;
	if (fetch_ask(ss, &ask) == 0) {
		close(fd);
		fetch_send_body(ss, -1, 0, 0, 0);
		return (0);
	}
	/* Send the descriptor the extent was checked on. */
	if (fw->wait_reply)
		fw->part_fd = fd;
	else
		close(fd);
	return (-1);
}

static void
fetch_send_parsed(struct store_session *ss, const char *text, uint32_t len)
{
	struct store_fetch_walk			*fw = &ss->fetch;
	struct imsg_mbox_fetch_bodystructure	 bsmeta;
	struct imsg_mbox_fetch_envelope		 envmeta;

	if (fw->stage == FETCH_STAGE_ENVELOPE) {
		memset(&envmeta, 0, sizeof(envmeta));
		envmeta.seqno = fw->meta.seqno;
		envmeta.uid = fw->rec.uid;
		envmeta.found = text != NULL;
		envmeta.envlen = len;
		fetch_send_part(ss, IMSG_MBOX_FETCH_ENVELOPE,
		    "IMSG_MBOX_FETCH_ENVELOPE", &envmeta, sizeof(envmeta),
		    envmeta.found, text, len);
		return;
	}
	memset(&bsmeta, 0, sizeof(bsmeta));
	bsmeta.seqno = fw->meta.seqno;
	bsmeta.uid = fw->rec.uid;
	bsmeta.found = text != NULL;
	bsmeta.bslen = len;
	fetch_send_part(ss, IMSG_MBOX_FETCH_BODYSTRUCTURE,
	    "IMSG_MBOX_FETCH_BODYSTRUCTURE", &bsmeta, sizeof(bsmeta),
	    bsmeta.found, text, len);
}

/*
 * ENVELOPE or BODYSTRUCTURE from the cache, else the parser.
 */
static int
fetch_parsed(struct store_session *ss, int item)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct parser_ask	 ask;
	const char		*text;
	uint32_t		 len = 0;
	int			 mfd, rc;

	if ((text = fetch_cached(ss, &fw->rec, item, &fw->have_file,
	    &len)) != NULL) {
		fetch_send_parsed(ss, text, len);
		return (0);
	}
	if ((mfd = open_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
	    fw->rec.basename)) == -1) {
		fetch_send_parsed(ss, NULL, 0);
		return (0);
	}
	memset(&ask, 0, sizeof(ask));
	if (item == PCACHE_ENVELOPE) {
		ask.type = IMSG_PARSER_ENVELOPE;
		ask.label = "ENVELOPE";
		ask.maxlen = ENVELOPE_MAX;
	} else {
		ask.type = IMSG_PARSER_BODYSTRUCTURE;
		ask.label = "BODYSTRUCTURE";
		ask.maxlen = BODYSTRUCTURE_MAX;
	}
	ask.fd = mfd;
	ask.basename = fw->rec.basename;
	rc = fetch_ask(ss, &ask);
	close(mfd);
	if (rc == 0)
		fetch_send_parsed(ss, NULL, 0);
	return (rc);
}

static void
fetch_send_meta(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_FETCH_META, 0, 0, -1,
	    &fw->meta, sizeof(fw->meta)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_FETCH_META",
		    ss->id);
	else {
		fw->sent++;
		fw->composed += sizeof(fw->meta);
	}
}

static int
fetch_walk_next(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct mbox_index	*idx = &fw->idx;
	struct imsg_mbox_fetch	*req = &fw->req;
	enum seqset_pos		 pos;
	uint32_t		 i;

	for (i = fw->next; i <= (uint32_t)idx->nlines; i++) {
		if (index_parse_line(idx->lines[i - 1], &fw->rec) == -1)
			continue;
		pos = seqset_position(fw->resolved, fw->nresolved, fw->max_hi,
		    req->by_uid, fw->rec.uid, i);
		if (pos == SEQSET_PAST_END)
			return (0);
		if (pos == SEQSET_SKIP)
			continue;
		if (req->has_changedsince &&
		    fw->rec.modseq <= req->changedsince)
			continue;
		fw->have_file = 0;
		if (fetch_meta(ss, &fw->rec, i, &fw->meta,
		    &fw->have_file) == -1)
			continue;
		fw->next = i + 1;
		fw->in_msg = 1;
		fw->stage = FETCH_STAGE_HEADER;
		return (1);
	}
	return (0);
}

static int
fetch_item(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	uint32_t		 a = fw->req.attrs;
	int			 rc = 0;

	switch (fw->stage) {
	case FETCH_STAGE_HEADER:
		if (a & (MBOX_FETCH_BODY_HEADER | MBOX_FETCH_HEADER_FIELDS))
			rc = fetch_header(ss);
		break;
	case FETCH_STAGE_BODY:
		if (a & (MBOX_FETCH_BODY_WHOLE | MBOX_FETCH_BODY_TEXT |
		    MBOX_FETCH_BODY_PART))
			rc = fetch_body(ss);
		break;
	case FETCH_STAGE_ENVELOPE:
		if (a & MBOX_FETCH_ENVELOPE)
			rc = fetch_parsed(ss, PCACHE_ENVELOPE);
		break;
	case FETCH_STAGE_BODYSTRUCTURE:
		if (a & MBOX_FETCH_BODYSTRUCTURE)
			rc = fetch_parsed(ss, PCACHE_BODYSTRUCTURE);
		break;
	default:
		fetch_send_meta(ss);
		fw->in_msg = 0;
		return (0);
	}
	if (rc == 0)
		fw->stage++;
	return (rc);
}

/*
 * Return, still active, at FETCH_BATCH_MAX or a due reply.
 */
static void
fetch_walk_step(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	while (!fw->wait_parser && !fw->wait_reply) {
		if (!fw->in_msg && !fetch_walk_next(ss)) {
			fetch_walk_finish(ss, 1);
			return;
		}
		if (fetch_item(ss) == -1)
			return;
		if (!fw->in_msg && (fw->composed >= FETCH_BATCH_MAX ||
		    fw->fds >= FETCH_FD_MAX))
			return;
	}
}

void
fetch_walk_parsed(struct store_session *ss, int rc,
    const struct imsg_parser_rep *rep, char *buf)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	fw->wait_reply = 0;
	switch (fw->stage) {
	case FETCH_STAGE_HEADER:
		fetch_send_header(ss, rc == 0, buf, rc == 0 ? rep->len : 0);
		break;
	case FETCH_STAGE_BODY:
		fetch_send_body(ss, fw->part_fd, rc == 0,
		    rc == 0 ? rep->part_off : 0, rc == 0 ? rep->part_len : 0);
		fw->part_fd = -1;
		break;
	default:
		if (rc == 0)
			pcache_put(ss->selected_mailbox, fw->idx.uidvalidity,
			    fw->rec.uid, fw->rec.basename,
			    fw->stage == FETCH_STAGE_ENVELOPE ?
			    PCACHE_ENVELOPE : PCACHE_BODYSTRUCTURE, buf,
			    rep->len);
		fetch_send_parsed(ss, rc == 0 ? buf : NULL,
		    rc == 0 ? rep->len : 0);
		break;
	}
	free(buf);
	fw->stage++;
	fetch_walk_step(ss);
}

static void
fetch_walk_finish(struct store_session *ss, int ok)
{
	struct store_fetch_walk	*fw = &ss->fetch;
	struct imsg_mbox_result	 result;
	struct imsgev		*iev = &ss->iev;

	index_free(&fw->idx);
	cur_snapshot_discard(&ss->cur_snap);

	memset(&result, 0, sizeof(result));
	result.error = !ok ? (fw->limit ? MBOX_OP_ERR_LIMIT :
	    MBOX_OP_ERR_GENERIC) : fw->ghost ?
	    MBOX_OP_ERR_EXPUNGEISSUED : MBOX_OP_OK;
	result.count = fw->sent;
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
	fw->active = 0;
}

int
fetch_walk_paused(struct store_session *ss)
{
	return (ss->fetch.active);
}

void
fetch_walk_resume(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	if (!fw->active || fw->wait_parser || fw->wait_reply)
		return;
	if (imsgbuf_queuelen(&ss->iev.ibuf) > 0)
		return;
	fw->composed = 0;
	fw->fds = 0;
	fetch_walk_step(ss);
}

void
fetch_walk_parser(struct store_session *ss, int ok)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	if (!fw->active || !fw->wait_parser)
		return;
	fw->wait_parser = 0;
	if (!ok)
		fw->no_parser = 1;
	fetch_walk_step(ss);
}

void
fetch_walk_abort(struct store_session *ss)
{
	struct store_fetch_walk	*fw = &ss->fetch;

	if (!fw->active)
		return;
	parser_cancel(ss);
	if (fw->part_fd != -1)
		close(fw->part_fd);
	fw->part_fd = -1;
	index_free(&fw->idx);
	fw->active = 0;
}

uint32_t
letters_to_sysflags(const char *letters)
{
	uint32_t	 f = 0;

	if (strchr(letters, 'D') != NULL)
		f |= MBOX_FLAG_DRAFT;
	if (strchr(letters, 'F') != NULL)
		f |= MBOX_FLAG_FLAGGED;
	if (strchr(letters, 'R') != NULL)
		f |= MBOX_FLAG_ANSWERED;
	if (strchr(letters, 'S') != NULL)
		f |= MBOX_FLAG_SEEN;
	if (strchr(letters, 'T') != NULL)
		f |= MBOX_FLAG_DELETED;
	return (f);
}

/*
 * Flag letters in ASCII order, as maildir requires.
 */
void
sysflags_to_letters(uint32_t sysflags, char *out, size_t outsize)
{
	size_t	 i = 0;

	if ((sysflags & MBOX_FLAG_DRAFT) && i + 1 < outsize)
		out[i++] = 'D';
	if ((sysflags & MBOX_FLAG_FLAGGED) && i + 1 < outsize)
		out[i++] = 'F';
	if ((sysflags & MBOX_FLAG_ANSWERED) && i + 1 < outsize)
		out[i++] = 'R';
	if ((sysflags & MBOX_FLAG_SEEN) && i + 1 < outsize)
		out[i++] = 'S';
	if ((sysflags & MBOX_FLAG_DELETED) && i + 1 < outsize)
		out[i++] = 'T';
	out[i] = '\0';
}

int
handle_mbox_status(struct imsg_mbox_status *req, struct store_session *ss)
{
	struct index_rec		 rec;
	struct imsgev			*iev = &ss->iev;
	struct mbox_index		 idx;
	struct imsg_mbox_status_result	 reply;
	struct index_lock		 il = INDEX_LOCK_INIT;
	const char			*target, *lp;
	char				 suffix[64];
	size_t				 i;
	off_t				 size;
	int				 tfd = -1, locked;
	uint32_t			 sysflags;

	memset(&reply, 0, sizeof(reply));

	if (mailbox_name_is_inbox(req->mailbox))
		target = "";
	else if (mailbox_name_valid(req->mailbox))
		target = req->mailbox;
	else {
		log_debug("session %u: STATUS %s: invalid mailbox name",
		    ss->id, req->mailbox);
		reply.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}
	if ((tfd = mailbox_open_dir(target)) == -1) {
		reply.error = errno == ENOENT || errno == ENOTDIR ?
		    MBOX_OP_ERR_NO_SUCH_MAILBOX : MBOX_OP_ERR_GENERIC;
		if (reply.error == MBOX_OP_ERR_GENERIC)
			log_warn("session %u: STATUS %s", ss->id,
			    req->mailbox);
		goto send;
	}

	locked = index_lock_acquire(tfd, &il, LOCK_EX | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY) {
		close(tfd);
		return (1);
	}
	if (locked == INDEX_LOCK_ERR) {
		reply.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (refresh_index(tfd, &idx, il.fd) == -1) {
		reply.error = errno == ENOSPC || errno == EDQUOT ?
		    MBOX_OP_ERR_OVERQUOTA : MBOX_OP_ERR_GENERIC;
		index_lock_release(&il);
		goto send;
	}

	reply.error = MBOX_OP_OK;
	reply.messages = (uint32_t)idx.nlines;
	reply.uidnext = idx.uidnext;
	reply.uidvalidity = idx.uidvalidity;
	reply.highestmodseq = idx.highestmodseq;

	if (req->attrs &
	    (STATUS_ATT_UNSEEN | STATUS_ATT_DELETED | STATUS_ATT_SIZE)) {
		for (i = 0; i < idx.nlines; i++) {
			if (index_parse_line(idx.lines[i], &rec) == -1)
				continue;
			if (locate_message_file(&ss->cur_snap, tfd,
			    rec.basename, &size, suffix,
			    sizeof(suffix)) == -1) {
				log_warnx("session %u: message %s indexed but "
				    "missing on disk, skipped (STATUS)",
				    ss->id, rec.basename);
				continue;
			}

			lp = strstr(suffix, "2,");
			sysflags = letters_to_sysflags(lp != NULL ?
			    lp + 2 : "");
			if (!(sysflags & MBOX_FLAG_SEEN))
				reply.unseen++;
			if (sysflags & MBOX_FLAG_DELETED)
				reply.deleted++;
			reply.size += (uint64_t)size;
		}
	}

	index_free(&idx);
	index_lock_release(&il);

send:
	if (tfd != -1)
		close(tfd);
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_STATUS_RESULT, 0, 0, -1, &reply,
	    sizeof(reply)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_STATUS_RESULT",
		    ss->id);
	return (0);
}
