#include <sys/types.h>
#include <sys/file.h>
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

struct store_step {
	uint32_t	 seqno;
	uint64_t	 modseq;
	int		 modified;	/* Failed UNCHANGEDSINCE */
	int		 changed;
	int		 needs_rename;
	int		 in_new;
	char		 oldsuffix[64];
	char		 letters[8];
	char		*newline;
};

struct expunged {
	char		*line;
	char		 suffix[64];
	uint32_t	 seqno;
};

struct expunge {
	struct seq_range	 resolved[SEQSET_MAX_RANGES];
	struct expunged		*gone;
	size_t			 ngone;
	size_t			 maxgone;
	uint32_t		 nresolved;
	uint32_t		 sent;
};

static int	 store_plan(struct store_session *,
		    const struct imsg_mbox_store *, const struct index_rec *,
		    uint64_t, struct store_step *, char *, size_t);
static int	 store_paths(const char *, const struct store_step *, char *,
		    size_t, char *, size_t);
static void	 store_undo(struct store_session *, const struct mbox_index *,
		    const struct store_step *, size_t);
static int	 expunge_select(struct store_session *,
		    const struct imsg_mbox_expunge *, struct mbox_index *,
		    struct expunge *);
static void	 expunge_remove(struct store_session *,
		    const struct imsg_mbox_expunge *, struct expunge *);

static int
store_plan(struct store_session *ss, const struct imsg_mbox_store *req,
    const struct index_rec *rec, uint64_t new_modseq, struct store_step *st,
    char *newline, size_t linesize)
{
	const char	*lp;
	uint32_t	 old_sysflags, new_sysflags;
	char		 suffix[64], newkeywords[MBOX_FLAGS_MAX];
	int		 len;

	if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
	    rec->basename, NULL, suffix, sizeof(suffix)) == -1) {
		log_warnx("session %u: message %s (uid %u) indexed but missing "
		    "on disk, skipped", ss->id, rec->basename, rec->uid);
		return (0);
	}
	st->in_new = (suffix[0] == '\0');
	(void)strlcpy(st->oldsuffix, suffix, sizeof(st->oldsuffix));

	lp = strstr(suffix, "2,");
	old_sysflags = letters_to_sysflags(lp != NULL ? lp + 2 : "");
	switch (req->mode) {
	case MBOX_STORE_SET:
		new_sysflags = req->sysflags;
		break;
	case MBOX_STORE_ADD:
		new_sysflags = old_sysflags | req->sysflags;
		break;
	case MBOX_STORE_REMOVE:
	default:
		new_sysflags = old_sysflags & ~req->sysflags;
		break;
	}

	/* Refuse rather than store a truncated list. */
	if (merge_keywords(req->mode, rec->keywords, req->keywords,
	    newkeywords, sizeof(newkeywords)) == -1) {
		log_warnx("session %u: STORE: uid %u: merged keywords over "
		    "%zu bytes", ss->id, rec->uid, sizeof(newkeywords));
		return (-1);
	}
	sysflags_to_letters(new_sysflags, st->letters, sizeof(st->letters));

	st->changed = new_sysflags != old_sysflags ||
	    strcmp(newkeywords, rec->keywords) != 0;
	st->modseq = st->changed ? new_modseq : rec->modseq;

	/* A touched message moves to cur/ with ":2," flags. */
	st->needs_rename = st->in_new ||
	    strcmp(lp != NULL ? lp + 2 : "", st->letters) != 0;

	len = snprintf(newline, linesize, "%u:%s:%s:%llu", rec->uid,
	    rec->basename, newkeywords, (unsigned long long)st->modseq);
	if (len < 0 || (size_t)len >= linesize) {
		log_warnx("session %u: new index line too long for %s",
		    ss->id, rec->basename);
		return (-1);
	}
	return (1);
}

static int
store_paths(const char *basename, const struct store_step *st,
    char *oldpath, size_t oldsize, char *newpath, size_t newsize)
{
	int	oldlen, newlen;

	oldlen = snprintf(oldpath, oldsize, "%s/%s%s",
	    st->in_new ? "new" : "cur", basename, st->oldsuffix);
	newlen = snprintf(newpath, newsize, "cur/%s:2,%s", basename,
	    st->letters);
	if (oldlen < 0 || (size_t)oldlen >= oldsize ||
	    newlen < 0 || (size_t)newlen >= newsize) {
		log_warnx("path too long for %s", basename);
		return (-1);
	}
	return (0);
}

static void
store_undo(struct store_session *ss, const struct mbox_index *idx,
    const struct store_step *steps, size_t nsteps)
{
	const struct store_step	*st;
	struct index_rec	 rec;
	size_t			 k;
	char			 oldpath[PATH_MAX], newpath[PATH_MAX];

	for (k = nsteps; k > 0; k--) {
		st = &steps[k - 1];

		if (st->modified || !st->needs_rename)
			continue;
		if (index_parse_line(idx->lines[st->seqno - 1], &rec) == -1 ||
		    store_paths(rec.basename, st, oldpath, sizeof(oldpath),
		    newpath, sizeof(newpath)) == -1)
			continue;
		if (renameat(ss->mailbox_dir_fd, newpath, ss->mailbox_dir_fd,
		    oldpath) == -1)
			log_warn("session %u: STORE rollback: rename %s -> %s, "
			    "left with the new flags", ss->id, newpath,
			    oldpath);
	}
}

/*
 * Plan every message before changing any.  Called with LOCK_EX held.
 */
int
store_apply(struct store_session *ss, const struct imsg_mbox_store *req,
    struct mbox_index *idx, const struct seq_range *resolved,
    uint32_t nresolved, int by_uid, int synced, const uint64_t *since,
    struct store_step **stepsp, size_t *nstepsp)
{
	struct store_step	*steps = NULL, *grown, st, *step;
	struct index_rec	 rec;
	enum seqset_pos		 pos;
	uint32_t		 i, max_hi;
	uint64_t		 new_modseq = idx->highestmodseq + 1;
	size_t			 nsteps = 0, maxsteps = 0, applied, k, newmax;
	char			 newline[STORE_INDEX_LINE_MAX];
	char			 oldpath[PATH_MAX], newpath[PATH_MAX];
	int			 ok = 1, changed = 0, rc;

	max_hi = seqset_max_hi(resolved, nresolved);
	for (i = 1; i <= (uint32_t)idx->nlines; i++) {
		if (index_parse_line(idx->lines[i - 1], &rec) == -1)
			continue;
		pos = seqset_position(resolved, nresolved, max_hi, by_uid,
		    rec.uid, i);
		if (pos == SEQSET_PAST_END)
			break;
		if (pos == SEQSET_SKIP ||
		    (since != NULL && rec.modseq <= *since))
			continue;

		memset(&st, 0, sizeof(st));
		st.seqno = i;
		if (req->has_unchangedsince &&
		    rec.modseq > req->unchangedsince) {
			st.modified = 1;
			st.modseq = rec.modseq;
		} else {
			rc = store_plan(ss, req, &rec, new_modseq, &st,
			    newline, sizeof(newline));
			if (rc == 0)
				continue;
			if (rc == -1 || (st.needs_rename &&
			    store_paths(rec.basename, &st, oldpath,
			    sizeof(oldpath), newpath, sizeof(newpath)) == -1)) {
				ok = 0;
				break;
			}
			if ((st.newline = strdup(newline)) == NULL) {
				log_warn("session %u: strdup index line",
				    ss->id);
				ok = 0;
				break;
			}
		}

		if (nsteps == maxsteps) {
			newmax = maxsteps ? maxsteps * 2 : 64;

			if ((grown = reallocarray(steps, newmax,
			    sizeof(*steps))) == NULL) {
				log_warn("session %u: STORE: reallocarray",
				    ss->id);
				free(st.newline);
				ok = 0;
				break;
			}
			steps = grown;
			maxsteps = newmax;
		}
		steps[nsteps++] = st;
	}

	for (applied = 0; ok && applied < nsteps; applied++) {
		step = &steps[applied];

		if (step->modified)
			continue;
		if (step->needs_rename) {
			if (index_parse_line(idx->lines[step->seqno - 1],
			    &rec) == -1 || store_paths(rec.basename, step,
			    oldpath, sizeof(oldpath), newpath,
			    sizeof(newpath)) == -1) {
				ok = 0;
				break;
			}
			if (renameat(ss->mailbox_dir_fd, oldpath,
			    ss->mailbox_dir_fd, newpath) == -1) {
				log_warn("session %u: rename %s -> %s",
				    ss->id, oldpath, newpath);
				ok = 0;
				break;
			}
		}
		free(idx->lines[step->seqno - 1]);
		idx->lines[step->seqno - 1] = step->newline;
		step->newline = NULL;
		if (step->changed)
			changed = 1;
	}
	for (k = 0; k < nsteps; k++) {
		free(steps[k].newline);
		steps[k].newline = NULL;
	}

	if (ok && changed) {
		idx->highestmodseq = new_modseq;
		if (index_save(ss->mailbox_dir_fd, idx) == -1)
			ok = 0;
	}
	if (!ok)
		store_undo(ss, idx, steps, applied);
	else if (synced && changed && new_modseq > ss->idle_baseline.modseq)
		/* Under LOCK_EX since the sync, so it is ours. */
		ss->idle_baseline.modseq = new_modseq;
	*stepsp = steps;
	*nstepsp = nsteps;
	return (ok);
}

int
handle_mbox_store(struct imsg_mbox_store *req, const struct seq_range *ranges,
    uint32_t nranges, struct store_session *ss)
{
	struct index_rec		 rec;
	struct imsg_mbox_store_modified	 mod;
	struct imsg_mbox_fetch_meta	 meta;
	struct imsgev			*iev = &ss->iev;
	struct mbox_index		 idx;
	struct imsg_mbox_result		 result;
	struct index_lock		 il = INDEX_LOCK_INIT;
	struct seq_range		 resolved[SEQSET_MAX_RANGES];
	struct seq_range		 vr[SEQSET_MAX_RANGES];
	struct store_step		*steps = NULL;
	const struct store_step		*st;
	char				 newsuffix[16];
	size_t				 nsteps = 0, k;
	uint64_t			 reported = 0;
	uint32_t			 nresolved, nvr, sent = 0;
	int				 ok = 1, by_uid, synced, used, rc;
	int				 ghost, limit = 0, locked;

	memset(&idx, 0, sizeof(idx));

	if (!index_field_valid(req->keywords)) {
		log_warnx("session %u: STORE: unsafe keywords field",
		    ss->id);
		ok = 0;
		goto done;
	}
	/* Nothing touched yet, so a busy return is free. */
	locked = index_lock_acquire(ss->mailbox_dir_fd, &il, LOCK_EX | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		return (1);
	if (locked == INDEX_LOCK_ERR) {
		ok = 0;
		goto done;
	}
	if (index_load(il.fd, &idx) == -1) {
		ok = 0;
		goto done;
	}

	synced = view_sync(ss, &idx, req->by_uid) == 0;
	by_uid = req->by_uid;
	if ((rc = saved_resolve(ss, ranges, nranges, vr, &nvr, &by_uid,
	    &used)) != 0) {
		limit = rc == -1;
		ok = 0;
		goto done;
	}

	reported = idx.highestmodseq;

	nresolved = seqset_resolve(vr, nvr, by_uid ?
	    index_max_uid(&idx) : (uint32_t)idx.nlines, !by_uid, resolved);
	ghost = !req->by_uid && !used && view_names_ghost(ss, &idx,
	    resolved, nresolved);

	ok = store_apply(ss, req, &idx, resolved, nresolved, by_uid, synced,
	    NULL, &steps, &nsteps);
	if (!ok)
		goto done;
	reported = idx.highestmodseq;

	for (k = 0; k < nsteps; k++) {
		st = &steps[k];

		if (index_parse_line(idx.lines[st->seqno - 1], &rec) == -1)
			continue;
		if (st->modified) {
			memset(&mod, 0, sizeof(mod));
			mod.seqno = view_seqno(ss, rec.uid, st->seqno);
			mod.uid = rec.uid;
			if (imsg_compose(&iev->ibuf, IMSG_MBOX_STORE_MODIFIED,
			    0, 0, -1, &mod, sizeof(mod)) == -1)
				log_warn("session %u: imsg_compose "
				    "IMSG_MBOX_STORE_MODIFIED", ss->id);
			continue;
		}

		/* With UNCHANGEDSINCE, .SILENT still returns the flags. */
		if (!req->silent || req->has_unchangedsince) {
			memset(&meta, 0, sizeof(meta));
			meta.seqno = view_seqno(ss, rec.uid, st->seqno);
			meta.uid = rec.uid;
			meta.modseq = st->modseq;
			(void)snprintf(newsuffix, sizeof(newsuffix), "2,%s",
			    st->letters);
			build_flags_string(newsuffix, rec.keywords, meta.flags,
			    sizeof(meta.flags));
			if (imsg_compose(&iev->ibuf, IMSG_MBOX_FETCH_META, 0, 0,
			    -1, &meta, sizeof(meta)) == -1)
				log_warn("session %u: imsg_compose "
				    "IMSG_MBOX_FETCH_META", ss->id);
			else
				sent++;
		}
	}

done:
	index_lock_release(&il);
	free(steps);

	memset(&result, 0, sizeof(result));
	/* RFC 2180 sections 4.2.1-4.2.3. */
	result.error = !ok ? (limit ? MBOX_OP_ERR_LIMIT :
	    MBOX_OP_ERR_GENERIC) : ghost && !req->silent ?
	    MBOX_OP_ERR_EXPUNGEISSUED : MBOX_OP_OK;
	result.count = sent;
	/* Only a value the index holds. */
	result.highestmodseq = reported;
	index_free(&idx);
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
	return (0);
}

static int
expunge_select(struct store_session *ss, const struct imsg_mbox_expunge *req,
    struct mbox_index *idx, struct expunge *ex)
{
	struct index_rec	 rec;
	struct expunged		*grown;
	const char		*lp;
	uint32_t		 sysflags;
	size_t			 in, out = 0, newmax;
	char			 suffix[64];
	int			 ok = 1;

	for (in = 0; in < idx->nlines; in++) {
		if (index_parse_line(idx->lines[in], &rec) == -1) {
			idx->lines[out++] = idx->lines[in];
			continue;
		}
		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec.basename, NULL, suffix, sizeof(suffix)) == -1) {
			log_warnx("session %u: message %s indexed but missing "
			    "on disk, kept, not expunged",
			    ss->id, rec.basename);
			idx->lines[out++] = idx->lines[in];
			continue;
		}
		lp = strstr(suffix, "2,");
		sysflags = letters_to_sysflags(lp != NULL ? lp + 2 : "");
		if (!(sysflags & MBOX_FLAG_DELETED)) {
			idx->lines[out++] = idx->lines[in];
			continue;
		}
		if (req->by_uid &&
		    !seqset_contains(ex->resolved, ex->nresolved, rec.uid)) {
			idx->lines[out++] = idx->lines[in];
			continue;
		}

		/* On failure, keep the message and fail the command. */
		if (ex->ngone == ex->maxgone) {
			newmax = ex->maxgone ? ex->maxgone * 2 : 64;
			if ((grown = reallocarray(ex->gone, newmax,
			    sizeof(*grown))) == NULL) {
				log_warn("session %u: EXPUNGE: reallocarray",
				    ss->id);
				ok = 0;
				idx->lines[out++] = idx->lines[in];
				continue;
			}
			ex->gone = grown;
			ex->maxgone = newmax;
		}
		ex->gone[ex->ngone].line = idx->lines[in];
		(void)strlcpy(ex->gone[ex->ngone].suffix, suffix,
		    sizeof(ex->gone[ex->ngone].suffix));
		ex->gone[ex->ngone].seqno = (uint32_t)(out + 1);
		ex->ngone++;
	}
	idx->nlines = out;
	return (ok ? 0 : -1);
}

static void
expunge_remove(struct store_session *ss, const struct imsg_mbox_expunge *req,
    struct expunge *ex)
{
	struct index_rec	 rec;
	size_t			 k;
	char			 path[PATH_MAX];
	int			 ret;

	for (k = 0; k < ex->ngone; k++) {
		if (index_parse_line(ex->gone[k].line, &rec) == -1)
			continue;
		pcache_drop_uid(ss->selected_mailbox, rec.uid);
		ret = snprintf(path, sizeof(path), "%s/%s%s",
		    ex->gone[k].suffix[0] == '\0' ? "new" : "cur",
		    rec.basename, ex->gone[k].suffix);
		if (ret < 0 || (size_t)ret >= sizeof(path))
			log_warnx("session %u: path too long for %s, left on "
			    "disk", ss->id, rec.basename);
		else if (unlinkat(ss->mailbox_dir_fd, path, 0) == -1 &&
		    errno != ENOENT)
			log_warn("session %u: unlink %s, left on disk with no "
			    "index entry", ss->id, path);

		if (!req->silent &&
		    send_expunged(ss, ex->gone[k].seqno, rec.uid) == 0)
			ex->sent++;
	}
}

/*
 * Save the compacted index before removing any file.
 */
int
handle_mbox_expunge(struct imsg_mbox_expunge *req,
    const struct seq_range *ranges, uint32_t nranges, struct store_session *ss)
{
	struct imsgev		*iev = &ss->iev;
	struct mbox_index	 idx;
	struct imsg_mbox_result	 result;
	struct index_lock	 il = INDEX_LOCK_INIT;
	struct expunge		 ex;
	struct seq_range	 vr[SEQSET_MAX_RANGES];
	size_t			 k;
	uint32_t		 nvr;
	uint64_t		 reported = 0;
	int			 ok = 1, locked, by_uid = 1, used, limit = 0;
	int			 rc;

	memset(&idx, 0, sizeof(idx));
	memset(&ex, 0, sizeof(ex));

	/* Nothing touched yet, so a busy return is free. */
	locked = index_lock_acquire(ss->mailbox_dir_fd, &il, LOCK_EX | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		return (1);
	if (locked == INDEX_LOCK_ERR) {
		ok = 0;
		goto done;
	}
	if (index_load(il.fd, &idx) == -1) {
		ok = 0;
		goto done;
	}
	reported = idx.highestmodseq;
	if (!req->silent)
		(void)view_sync(ss, &idx, 1);

	if (req->by_uid) {
		if ((rc = saved_resolve(ss, ranges, nranges, vr, &nvr, &by_uid,
		    &used)) != 0) {
			limit = rc == -1;
			ok = 0;
			goto done;
		}
		ex.nresolved = seqset_resolve(vr, nvr, index_max_uid(&idx), 0,
		    ex.resolved);
	}

	if (expunge_select(ss, req, &idx, &ex) == -1)
		ok = 0;
	if (ok && ex.ngone > 0) {
		idx.highestmodseq++;
		if (index_save(ss->mailbox_dir_fd, &idx) == -1)
			ok = 0;
	}
	if (!ok) {
		goto done;
	}
	reported = idx.highestmodseq;
	expunge_remove(ss, req, &ex);

done:
	/* CLOSE deselects once its expunge is saved. */
	if (req->silent && ok)
		ss->mailbox_selected = 0;

	index_lock_release(&il);

	memset(&result, 0, sizeof(result));
	result.error = ok ? MBOX_OP_OK : limit ? MBOX_OP_ERR_LIMIT :
	    MBOX_OP_ERR_GENERIC;
	result.count = ex.sent;
	result.highestmodseq = reported;
	index_free(&idx);
	for (k = 0; k < ex.ngone; k++)
		free(ex.gone[k].line);
	free(ex.gone);
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
	return (0);
}
