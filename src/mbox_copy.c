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

/* The two mailboxes of a COPY or MOVE. */
struct copy_move {
	struct mbox_index	 idx_a, idx_b;
	struct mbox_index	*srcidx, *destidx;
	struct index_lock	 il_a, il_b;
	struct imsg_mbox_result	 result;
	char			 desttarget[MBOX_NAME_MAX];
	int			 destfd;
	int			 cross_mailbox;
};

struct moved {
	uint32_t	old_uid;
	uint32_t	old_seqno;
	uint32_t	dest_uid;
	char		basename[NAME_MAX + 1];
	char		keywords[512];
};

static int	 resolve_mailbox_target(const char *, char *, size_t);
static int	 stage_copy_messages(struct store_session *,
		    struct mbox_index *, struct imsg_mbox_copy *,
		    const struct seq_range *, uint32_t, struct copy_staged **,
		    size_t *);
static int	 copy_message_file(struct store_session *,
		    const struct copy_staged *, int, const char *);
static int	 commit_copy_messages(struct store_session *, int,
		    struct mbox_index *, struct copy_staged *, size_t);
static int	 copy_move_lock(struct store_session *, const char *,
		    const char *, struct copy_move *);
static void	 copy_move_finish(struct copy_move *, int,
		    struct store_session *);
static size_t	 compaction_bail(struct mbox_index *, size_t, size_t);
static int	 move_same_mailbox(struct imsg_mbox_copy *,
		    const struct seq_range *, uint32_t, struct mbox_index *,
		    uint32_t *, struct store_session *);
static int	 move_cross_mailbox(struct imsg_mbox_copy *,
		    const struct seq_range *, uint32_t, struct copy_move *,
		    uint32_t *, struct store_session *);

static int
resolve_mailbox_target(const char *name, char *target, size_t targetlen)
{
	if (mailbox_name_is_inbox(name)) {
		target[0] = '\0';
		return (0);
	}
	if (mailbox_name_valid(name)) {
		if (strlcpy(target, name, targetlen) >= targetlen)
			return (-1);
		return (0);
	}
	return (-1);
}

static int
stage_copy_messages(struct store_session *ss, struct mbox_index *idx,
    struct imsg_mbox_copy *req, const struct seq_range *ranges,
    uint32_t nranges, struct copy_staged **staged_out, size_t *nstaged_out)
{
	struct copy_staged	*staged = NULL, cs, *newstaged;
	struct index_rec	 rec;
	struct seq_range	 resolved[SEQSET_MAX_RANGES];
	enum seqset_pos		 pos;
	const char		*lp;
	uint32_t		 nresolved, max_hi;
	size_t			 nstaged = 0, stagedcap = 0, i, newcap;
	off_t			 size;
	char			 suffix[64], path[PATH_MAX];
	int			 ret;

	nresolved = seqset_resolve(ranges, nranges, req->by_uid ?
	    index_max_uid(idx) : (uint32_t)idx->nlines, !req->by_uid,
	    resolved);
	max_hi = seqset_max_hi(resolved, nresolved);

	for (i = 0; i < idx->nlines; i++) {
		if (index_parse_line(idx->lines[i], &rec) == -1)
			continue;

		pos = seqset_position(resolved, nresolved, max_hi, req->by_uid,
		    rec.uid, (uint32_t)(i + 1));
		if (pos == SEQSET_PAST_END)
			break;
		if (pos == SEQSET_SKIP)
			continue;

		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec.basename, &size, suffix, sizeof(suffix)) == -1) {
			log_warnx("session %u: COPY: message %s indexed but "
			    "missing on disk, COPY failed",
			    ss->id, rec.basename);
			goto fail;
		}

		memset(&cs, 0, sizeof(cs));
		cs.src_uid = rec.uid;
		strlcpy(cs.keywords, rec.keywords, sizeof(cs.keywords));
		/* Refuse before any file is written. */
		if (!index_field_valid(cs.keywords)) {
			log_warnx("session %u: COPY: unsafe keywords field on "
			    "%s, failing COPY", ss->id, rec.basename);
			goto fail;
		}
		lp = strstr(suffix, "2,");
		cs.sysflags = letters_to_sysflags(lp != NULL ? lp + 2 : "");

		ret = snprintf(cs.basename, sizeof(cs.basename),
		    "%lld.%d_%u.%s",
		    (long long)parse_maildir_timestamp(rec.basename),
		    (int)getpid(), append_counter++, append_hostname());
		if (ret < 0 || (size_t)ret >= sizeof(cs.basename)) {
			log_warnx("session %u: COPY: generated basename too "
			    "long", ss->id);
			goto fail;
		}
		if (!index_basename_valid(cs.basename)) {
			log_warnx("session %u: COPY: unsafe generated basename",
			    ss->id);
			goto fail;
		}

		ret = snprintf(path, sizeof(path), "%s/%s%s",
		    suffix[0] == '\0' ? "new" : "cur", rec.basename, suffix);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			log_warnx("session %u: COPY: source path too long "
			    "for %s", ss->id, rec.basename);
			goto fail;
		}
		if ((cs.srcpath = strdup(path)) == NULL) {
			log_warn("session %u: COPY: strdup source path",
			    ss->id);
			goto fail;
		}
		cs.srcsize = size;

		if (nstaged == stagedcap) {
			newcap = (stagedcap == 0) ? 8 :
			    stagedcap * 2;

			newstaged = reallocarray(staged, newcap,
			    sizeof(*staged));
			if (newstaged == NULL) {
				log_warn("session %u: COPY: reallocarray "
				    "staged", ss->id);
				free(cs.srcpath);
				goto fail;
			}
			staged = newstaged;
			stagedcap = newcap;
		}
		staged[nstaged++] = cs;
	}

	*staged_out = staged;
	*nstaged_out = nstaged;
	return (1);

fail:
	for (i = 0; i < nstaged; i++)
		free(staged[i].srcpath);
	free(staged);
	*staged_out = NULL;
	*nstaged_out = 0;
	return (0);
}

/*
 * When linkat(2) fails, copy through tmp/ as APPEND does.
 */
static int
copy_message_file(struct store_session *ss, const struct copy_staged *cs,
    int dfd, const char *curpath)
{
	static char	 buf[STORE_READ_BLOCK];
	ssize_t		 n, w;
	size_t		 want, written;
	off_t		 left = cs->srcsize;
	char		 tmppath[PATH_MAX];
	int		 srcfd, tmpfd, ret;

	ret = snprintf(tmppath, sizeof(tmppath), "tmp/%s", cs->basename);
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		log_warnx("session %u: COPY: tmp path too long", ss->id);
		return (-1);
	}
	if ((srcfd = openat(ss->mailbox_dir_fd, cs->srcpath, O_RDONLY)) == -1) {
		log_warn("session %u: COPY: open %s", ss->id, cs->srcpath);
		return (-1);
	}
	if ((tmpfd = openat(dfd, tmppath, O_WRONLY | O_CREAT | O_EXCL,
	    0600)) == -1) {
		log_warn("session %u: COPY: open %s", ss->id, tmppath);
		close(srcfd);
		return (-1);
	}
	while (left > 0) {
		written = 0;

		want = left < (off_t)sizeof(buf) ? (size_t)left : sizeof(buf);
		if ((n = read(srcfd, buf, want)) == -1) {
			if (errno == EINTR)
				continue;
			log_warn("session %u: COPY: read %s", ss->id,
			    cs->srcpath);
			goto fail;
		}
		/* A copy now would be partial. */
		if (n == 0) {
			log_warnx("session %u: COPY: %s shrank during copy, "
			    "failing COPY", ss->id, cs->srcpath);
			goto fail;
		}
		while (written < (size_t)n) {
			if ((w = write(tmpfd, buf + written,
			    (size_t)n - written)) == -1) {
				if (errno == EINTR)
					continue;
				log_warn("session %u: COPY: write %s",
				    ss->id, tmppath);
				goto fail;
			}
			written += (size_t)w;
		}
		left -= n;
	}
	if (fsync(tmpfd) == -1) {
		log_warn("session %u: COPY: fsync %s", ss->id, tmppath);
		goto fail;
	}
	if (close(tmpfd) == -1) {
		log_warn("session %u: COPY: close %s", ss->id, tmppath);
		tmpfd = -1;
		goto fail;
	}
	close(srcfd);
	if (renameat(dfd, tmppath, dfd, curpath) == -1) {
		log_warn("session %u: COPY: rename %s -> %s", ss->id,
		    tmppath, curpath);
		unlinkat(dfd, tmppath, 0);
		return (-1);
	}
	return (0);

fail:
	if (tmpfd != -1)
		close(tmpfd);
	close(srcfd);
	unlinkat(dfd, tmppath, 0);
	return (-1);
}

static int
commit_copy_messages(struct store_session *ss, int dfd,
    struct mbox_index *destidx, struct copy_staged *staged, size_t nstaged)
{
	struct imsg_mbox_copy_mapping	mapping;
	char				curpath[PATH_MAX], letters[8];
	char				line[STORE_INDEX_LINE_MAX];
	size_t				i;
	/* Entries whose file is already in cur/. */
	size_t				ncommitted = 0;
	int				ret, n;
	uint32_t			dest_uid;

	for (i = 0; i < nstaged; i++) {
		sysflags_to_letters(staged[i].sysflags, letters,
		    sizeof(letters));
		ret = snprintf(curpath, sizeof(curpath), "cur/%s:2,%s",
		    staged[i].basename, letters);
		if (ret < 0 || (size_t)ret >= sizeof(curpath)) {
			log_warnx("session %u: COPY: cur path too long",
			    ss->id);
			goto rollback;
		}
		/* A maildir message is not rewritten, only linked. */
		if (linkat(ss->mailbox_dir_fd, staged[i].srcpath, dfd, curpath,
		    AT_SYMLINK_FOLLOW) == -1) {
			/* A rename would replace the existing file. */
			if (errno == EEXIST) {
				log_warn("session %u: COPY: link %s -> %s",
				    ss->id, staged[i].srcpath, curpath);
				goto rollback;
			}
			log_debug("session %u: COPY: link %s: %s, copying "
			    "instead", ss->id, staged[i].srcpath,
			    strerror(errno));
			if (copy_message_file(ss, &staged[i], dfd,
			    curpath) == -1)
				goto rollback;
		}
		ncommitted = i + 1;
	}

	for (i = 0; i < nstaged; i++) {
		dest_uid = destidx->uidnext;

		if (!index_basename_valid(staged[i].basename) ||
		    !index_field_valid(staged[i].keywords)) {
			log_warnx("session %u: COPY: unsafe field in staged "
			    "message", ss->id);
			goto rollback;
		}

		if (index_append(destidx, dest_uid, staged[i].basename) ==
		    -1)
			goto rollback;
		destidx->uidnext++;
		staged[i].dest_uid = dest_uid;

		if (staged[i].keywords[0] != '\0') {
			n = snprintf(line, sizeof(line), "%u:%s:%s:%llu",
			    dest_uid, staged[i].basename, staged[i].keywords,
			    (unsigned long long)destidx->highestmodseq);
			if (n < 0 || (size_t)n >= sizeof(line)) {
				log_warnx("session %u: COPY: index line too "
				    "long", ss->id);
				goto rollback;
			}
			free(destidx->lines[destidx->nlines - 1]);
			if ((destidx->lines[destidx->nlines - 1] =
			    strdup(line)) == NULL) {
				log_warn("session %u: COPY: strdup index "
				    "line", ss->id);
				goto rollback;
			}
		}
	}

	if (index_save(dfd, destidx) == -1)
		goto rollback;

	for (i = 0; i < nstaged; i++) {
		memset(&mapping, 0, sizeof(mapping));
		mapping.src_uid = staged[i].src_uid;
		mapping.dest_uid = staged[i].dest_uid;
		if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_COPY_MAPPING, 0, 0,
		    -1, &mapping, sizeof(mapping)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_COPY_MAPPING", ss->id);
	}

	return (1);

rollback:
	/* A COPY is all or nothing. */
	while (ncommitted > 0) {
		ncommitted--;
		sysflags_to_letters(staged[ncommitted].sysflags, letters,
		    sizeof(letters));
		ret = snprintf(curpath, sizeof(curpath), "cur/%s:2,%s",
		    staged[ncommitted].basename, letters);
		if (ret < 0 || (size_t)ret >= sizeof(curpath))
			continue;	/* So it was not created either. */
		if (unlinkat(dfd, curpath, 0) == -1 && errno != ENOENT)
			log_warn("session %u: COPY: rollback unlink %s",
			    ss->id, curpath);
	}
	return (0);
}

#define COPY_MOVE_FAIL	0
#define COPY_MOVE_READY	1
#define COPY_MOVE_BUSY	2

static int
copy_move_lock(struct store_session *ss, const char *what,
    const char *destname, struct copy_move *cm)
{
	static const struct index_lock	 il_init = INDEX_LOCK_INIT;
	int				 firstfd, secondfd, first_is_dest;
	int				 locked;

	memset(cm, 0, sizeof(*cm));
	cm->il_a = il_init;
	cm->il_b = il_init;
	cm->destfd = -1;

	if (resolve_mailbox_target(destname, cm->desttarget,
	    sizeof(cm->desttarget)) == -1) {
		log_debug("session %u: %s %s: invalid destination mailbox "
		    "name", ss->id, what, destname);
		cm->result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		return (COPY_MOVE_FAIL);
	}
	cm->cross_mailbox = (strcmp(ss->selected_mailbox, cm->desttarget) != 0);

	if (!cm->cross_mailbox) {
		locked = index_lock_acquire(ss->mailbox_dir_fd, &cm->il_a,
		    LOCK_EX | LOCK_NB);
		if (locked == INDEX_LOCK_BUSY)
			return (COPY_MOVE_BUSY);
		if (locked == INDEX_LOCK_ERR)
			return (COPY_MOVE_FAIL);
		if (index_load(cm->il_a.fd, &cm->idx_a) == -1)
			return (COPY_MOVE_FAIL);
		cm->srcidx = &cm->idx_a;
		cm->destidx = &cm->idx_a;
		return (COPY_MOVE_READY);
	}

	if ((cm->destfd = mailbox_open_dir(cm->desttarget)) == -1) {
		log_debug("session %u: %s: no such mailbox %s", ss->id,
		    what, cm->desttarget);
		cm->result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		return (COPY_MOVE_FAIL);
	}

	/* Lock in name order, against AB-BA deadlock. */
	first_is_dest = strcmp(ss->selected_mailbox, cm->desttarget) > 0;
	firstfd = first_is_dest ? cm->destfd : ss->mailbox_dir_fd;
	secondfd = first_is_dest ? ss->mailbox_dir_fd : cm->destfd;

	locked = index_lock_acquire(firstfd, &cm->il_a, LOCK_EX | LOCK_NB);
	if (locked != INDEX_LOCK_OK)
		goto fail;
	if (index_load(cm->il_a.fd, &cm->idx_a) == -1)
		goto fail;
	locked = index_lock_acquire(secondfd, &cm->il_b, LOCK_EX | LOCK_NB);
	if (locked != INDEX_LOCK_OK)
		goto fail;
	if (index_load(cm->il_b.fd, &cm->idx_b) == -1)
		goto fail;

	cm->srcidx = first_is_dest ? &cm->idx_b : &cm->idx_a;
	cm->destidx = first_is_dest ? &cm->idx_a : &cm->idx_b;
	return (COPY_MOVE_READY);

fail:
	close(cm->destfd);
	cm->destfd = -1;
	if (locked == INDEX_LOCK_BUSY) {
		/* Release both, so a retry starts clean. */
		index_lock_release(&cm->il_a);
		index_free(&cm->idx_a);
		memset(&cm->idx_a, 0, sizeof(cm->idx_a));
		return (COPY_MOVE_BUSY);
	}
	return (COPY_MOVE_FAIL);
}

static void
copy_move_finish(struct copy_move *cm, int ok, struct store_session *ss)
{
	if (cm->destfd != -1)
		close(cm->destfd);
	index_lock_release(&cm->il_a);
	index_lock_release(&cm->il_b);

	if (cm->result.error != MBOX_OP_ERR_NO_SUCH_MAILBOX &&
	    cm->result.error != MBOX_OP_ERR_LIMIT &&
	    cm->result.error != MBOX_OP_ERR_OVERQUOTA)
		cm->result.error = ok ? MBOX_OP_OK : MBOX_OP_ERR_GENERIC;
	index_free(&cm->idx_a);
	index_free(&cm->idx_b);

	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &cm->result,
	    sizeof(cm->result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

int
handle_mbox_copy(struct imsg_mbox_copy *req, const struct seq_range *ranges,
    uint32_t nranges, struct store_session *ss)
{
	struct copy_staged	*staged = NULL;
	struct copy_move	 cm;
	struct seq_range	 vr[SEQSET_MAX_RANGES];
	uint32_t		 nvr;
	size_t			 nstaged = 0, i;
	int			 ok = 1, dfd, got, used;

	got = copy_move_lock(ss, "COPY", req->destname, &cm);
	if (got == COPY_MOVE_BUSY)
		return (1);
	if (got == COPY_MOVE_FAIL) {
		ok = 0;
		goto done;
	}
	dfd = cm.cross_mailbox ? cm.destfd : ss->mailbox_dir_fd;
	if (!store_space_ok(dfd)) {
		cm.result.error = MBOX_OP_ERR_OVERQUOTA;
		ok = 0;
		goto done;
	}
	/* RFC 2180 section 4.4.2: numbers before the EXPUNGEs. */
	if ((got = saved_resolve(ss, ranges, nranges, vr, &nvr,
	    &req->by_uid, &used)) != 0) {
		if (got == -1)
			cm.result.error = MBOX_OP_ERR_LIMIT;
		ok = 0;
		goto done;
	}
	(void)view_sync(ss, cm.srcidx, 1);

	if (!stage_copy_messages(ss, cm.srcidx, req, vr, nvr, &staged,
	    &nstaged)) {
		ok = 0;
		goto done;
	}
	if (nstaged > 0 && (ensure_maildir_dirs(dfd, "") == -1 ||
	    !commit_copy_messages(ss, dfd, cm.destidx, staged, nstaged)))
		ok = 0;
	if (ok) {
		cm.result.count = (uint32_t)nstaged;
		cm.result.uidvalidity = cm.destidx->uidvalidity;
		cm.result.highestmodseq = cm.srcidx->highestmodseq;
	}

done:
	for (i = 0; i < nstaged; i++)
		free(staged[i].srcpath);
	free(staged);
	copy_move_finish(&cm, ok, ss);
	return (0);
}

static size_t
compaction_bail(struct mbox_index *idx, size_t dropped, size_t out)
{
	size_t	j;

	for (j = dropped + 1; j < idx->nlines; j++)
		idx->lines[out++] = idx->lines[j];
	idx->nlines = out;
	return (out);
}

static int
move_same_mailbox(struct imsg_mbox_copy *req, const struct seq_range *ranges,
    uint32_t nranges, struct mbox_index *idx, uint32_t *nmoved_out,
    struct store_session *ss)
{
	struct index_rec		 rec;
	struct imsg_mbox_copy_mapping	 mapping;
	struct imsgev			*iev = &ss->iev;
	struct moved			*moved = NULL, *newmoved;
	char				 line[STORE_INDEX_LINE_MAX];
	size_t				 nmoved = 0, movedcap = 0, in, out, i;
	struct seq_range		 resolved[SEQSET_MAX_RANGES];
	size_t				 newcap;
	uint32_t			 nresolved, dest_uid;
	int				 ok = 1, matched, n;

	*nmoved_out = 0;

	nresolved = seqset_resolve(ranges, nranges, req->by_uid ?
	    index_max_uid(idx) : (uint32_t)idx->nlines, !req->by_uid,
	    resolved);

	out = 0;
	for (in = 0; in < idx->nlines; in++) {
		if (index_parse_line(idx->lines[in], &rec) == -1) {
			idx->lines[out++] = idx->lines[in];
			continue;
		}

		if (req->by_uid)
			matched = seqset_contains(resolved, nresolved,
			    rec.uid);
		else
			matched = seqset_contains(resolved, nresolved,
			    (uint32_t)(in + 1));

		if (!matched) {
			idx->lines[out++] = idx->lines[in];
			continue;
		}

		if (nmoved == movedcap) {
			newcap = (movedcap == 0) ? 8 :
			    movedcap * 2;

			newmoved = reallocarray(moved, newcap, sizeof(*moved));
			if (newmoved == NULL) {
				log_warn("session %u: MOVE: reallocarray "
				    "moved", ss->id);
				free(idx->lines[in]);
				out = compaction_bail(idx, in, out);
				ok = 0;
				goto done;
			}
			moved = newmoved;
			movedcap = newcap;
		}
		moved[nmoved].old_uid = rec.uid;
		moved[nmoved].old_seqno = (uint32_t)(out + 1);
		strlcpy(moved[nmoved].basename, rec.basename,
		    sizeof(moved[nmoved].basename));
		strlcpy(moved[nmoved].keywords, rec.keywords,
		    sizeof(moved[nmoved].keywords));
		nmoved++;

		free(idx->lines[in]);
	}
	idx->nlines = out;

	for (i = 0; i < nmoved; i++) {
		dest_uid = idx->uidnext;

		if (!index_basename_valid(moved[i].basename) ||
		    !index_field_valid(moved[i].keywords)) {
			log_warnx("session %u: MOVE: unsafe field in moved "
			    "message", ss->id);
			ok = 0;
			goto done;
		}

		if (index_append(idx, dest_uid, moved[i].basename) == -1) {
			ok = 0;
			goto done;
		}
		idx->uidnext++;
		moved[i].dest_uid = dest_uid;

		if (moved[i].keywords[0] != '\0') {
			n = snprintf(line, sizeof(line), "%u:%s:%s:%llu",
			    dest_uid, moved[i].basename, moved[i].keywords,
			    (unsigned long long)idx->highestmodseq);
			if (n < 0 || (size_t)n >= sizeof(line)) {
				log_warnx("session %u: MOVE: index line too "
				    "long", ss->id);
				ok = 0;
				goto done;
			}
			free(idx->lines[idx->nlines - 1]);
			if ((idx->lines[idx->nlines - 1] = strdup(line)) ==
			    NULL) {
				log_warn("session %u: MOVE: strdup index "
				    "line", ss->id);
				ok = 0;
				goto done;
			}
		}
	}

	if (index_save(ss->mailbox_dir_fd, idx) == -1) {
		ok = 0;
		goto done;
	}

	for (i = 0; i < nmoved; i++) {
		memset(&mapping, 0, sizeof(mapping));
		mapping.src_uid = moved[i].old_uid;
		mapping.dest_uid = moved[i].dest_uid;
		if (imsg_compose(&iev->ibuf, IMSG_MBOX_COPY_MAPPING, 0, 0, -1,
		    &mapping, sizeof(mapping)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_COPY_MAPPING", ss->id);
	}
	/* COPYUID goes out before the EXPUNGEs. */
	for (i = 0; i < nmoved; i++) {
		pcache_drop_uid(ss->selected_mailbox, moved[i].old_uid);
		(void)send_expunged(ss, moved[i].old_seqno, moved[i].old_uid);
	}

done:
	*nmoved_out = (uint32_t)nmoved;
	free(moved);
	return (ok);
}

/*
 * The destination commits before the source loses anything.
 */
static int
move_cross_mailbox(struct imsg_mbox_copy *req, const struct seq_range *ranges,
    uint32_t nranges, struct copy_move *cm, uint32_t *nmoved_out,
    struct store_session *ss)
{
	struct index_rec	 rec;
	struct mbox_index	*srcidx = cm->srcidx;
	struct copy_staged	*staged = NULL;
	char			 suffix[64], path[PATH_MAX];
	size_t			 nstaged = 0, i, j, out;
	off_t			 size;
	int			 ok = 1, any_removed = 0, ret, found;
	uint32_t		 old_seqno;

	*nmoved_out = 0;

	if (!stage_copy_messages(ss, srcidx, req, ranges, nranges, &staged,
	    &nstaged))
		return (0);

	if (nstaged == 0)
		return (1);

	if (ensure_maildir_dirs(cm->destfd, "") == -1) {
		ok = 0;
		goto cleanup;
	}
	if (!commit_copy_messages(ss, cm->destfd, cm->destidx, staged,
	    nstaged)) {
		ok = 0;
		goto cleanup;
	}

	for (i = 0; i < nstaged; i++) {
		old_seqno = 0;
		found = 0;

		for (j = 0, out = 0; j < srcidx->nlines; j++) {
			if (!found && index_parse_line(srcidx->lines[j],
			    &rec) == 0 && rec.uid == staged[i].src_uid) {
				old_seqno = (uint32_t)(out + 1);
				found = 1;
				free(srcidx->lines[j]);
				continue;
			}
			srcidx->lines[out++] = srcidx->lines[j];
		}
		srcidx->nlines = out;

		if (!found) {
			/* Another session removed it, and the copy stands. */
			continue;
		}
		any_removed = 1;
		pcache_drop_uid(ss->selected_mailbox, staged[i].src_uid);

		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec.basename, &size, suffix, sizeof(suffix)) == 0) {
			ret = snprintf(path, sizeof(path), "%s/%s%s",
			    suffix[0] == '\0' ? "new" : "cur", rec.basename,
			    suffix);
			if (ret < 0 || (size_t)ret >= sizeof(path))
				log_warnx("session %u: MOVE: path too long "
				    "for %s, left on disk", ss->id,
				    rec.basename);
			else if (unlinkat(ss->mailbox_dir_fd, path, 0) == -1 &&
			    errno != ENOENT)
				log_warn("session %u: MOVE: unlink %s, left "
				    "on disk", ss->id, path);
		}

		(void)send_expunged(ss, old_seqno, staged[i].src_uid);
	}

	/* A removal raises HIGHESTMODSEQ. */
	if (any_removed)
		srcidx->highestmodseq++;

	if (index_save(ss->mailbox_dir_fd, srcidx) == -1) {
		log_warnx("session %u: MOVE: source index not saved after "
		    "commit, duplicates possible", ss->id);
		ok = 0;
		goto cleanup;
	}

	*nmoved_out = (uint32_t)nstaged;

cleanup:
	for (i = 0; i < nstaged; i++)
		free(staged[i].srcpath);
	free(staged);
	return (ok);
}

int
handle_mbox_move(struct imsg_mbox_copy *req, const struct seq_range *ranges,
    uint32_t nranges, struct store_session *ss)
{
	struct copy_move	 cm;
	struct seq_range	 vr[SEQSET_MAX_RANGES];
	uint32_t		 nmoved = 0, nvr;
	int			 ok = 1, got, used;

	got = copy_move_lock(ss, "MOVE", req->destname, &cm);
	if (got == COPY_MOVE_BUSY)
		return (1);
	if (got == COPY_MOVE_FAIL) {
		ok = 0;
		goto done;
	}
	if (cm.cross_mailbox && !store_space_ok(cm.destfd)) {
		cm.result.error = MBOX_OP_ERR_OVERQUOTA;
		ok = 0;
		goto done;
	}
	if ((got = saved_resolve(ss, ranges, nranges, vr, &nvr,
	    &req->by_uid, &used)) != 0) {
		if (got == -1)
			cm.result.error = MBOX_OP_ERR_LIMIT;
		ok = 0;
		goto done;
	}
	(void)view_sync(ss, cm.srcidx, 1);
	if (!cm.cross_mailbox) {
		if (!move_same_mailbox(req, vr, nvr, cm.srcidx, &nmoved, ss))
			ok = 0;
	} else if (!move_cross_mailbox(req, vr, nvr, &cm, &nmoved, ss))
		ok = 0;

	if (ok) {
		cm.result.count = nmoved;
		cm.result.uidvalidity = cm.destidx->uidvalidity;
		cm.result.highestmodseq = cm.srcidx->highestmodseq;
	}

done:
	copy_move_finish(&cm, ok, ss);
	return (0);
}
