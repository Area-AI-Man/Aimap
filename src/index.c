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

/* A mod-sequence is a positive 63-bit integer. */
#define INDEX_MODSEQ_MAX	INT64_MAX

struct base_set {
	const char	**name;
	size_t		 *len;
	size_t		  mask;
};

static uint32_t	 uidvalidity_next(void);
static int	 index_lines_grow(struct mbox_index *);
static int	 index_has_basename(struct mbox_index *, const char *);
static int	 to_crlf(int, const char *, const char *);
static void	 new_to_cur(int, const char *);
static int	 index_scan_new(int, struct mbox_index *, int);
static size_t	 base_slot(const struct base_set *, const char *, size_t);
static int	 name_cmp(const void *, const void *);
static int	 index_scan_cur(int, struct mbox_index *, int);
static int	 index_scan(int, struct mbox_index *, int);
static size_t	 uid_find(const uint32_t *, size_t, uint32_t);
static size_t	 view_merge(const uint32_t *, size_t, const uint32_t *, size_t,
		    int, uint32_t *, size_t *, struct store_session *);
static size_t	 view_send_flag_fetches(const struct mbox_index *,
		    const uint32_t *, size_t, uint64_t, const uint32_t *,
		    size_t, struct store_session *);
static int	 idle_probe_unchanged(struct store_session *);
static int	 idle_uid_list(const struct mbox_index *, uint32_t **, size_t *,
		    uint64_t *);
static int	 idle_seed_unlocked(struct store_session *);

int
index_field_valid(const char *field)
{
	return (field != NULL && strpbrk(field, ":\r\n") == NULL);
}

/*
 * Keep names inside this mailbox, which unveil(2) cannot do.
 */
int
index_basename_valid(const char *basename)
{
	const unsigned char	*p;

	if (!index_field_valid(basename))
		return (0);
	/* Rejects empty names, dot entries and dotfiles at once. */
	if (basename[0] == '\0' || basename[0] == '.')
		return (0);
	for (p = (const unsigned char *)basename; *p != '\0'; p++) {
		if (*p == '/' || *p < 0x20 || *p == 0x7f)
			return (0);
	}
	return (1);
}

static int
index_lines_grow(struct mbox_index *idx)
{
	size_t	  newcap;
	char	**newlines;

	if (idx->nlines < idx->cap)
		return (0);

	newcap = (idx->cap == 0) ? 16 : idx->cap * 2;
	if ((newlines = reallocarray(idx->lines, newcap,
	    sizeof(*idx->lines))) == NULL) {
		log_warn("reallocarray index");
		return (-1);
	}
	idx->lines = newlines;
	idx->cap = newcap;
	return (0);
}

int
index_load(int fd, struct mbox_index *idx)
{
	unsigned long	 uid, lastuid = 0;
	const char	*errstr;
	ssize_t		 linelen;
	size_t		 linesize = 0;
	FILE		*fp;
	char		*line = NULL, *colon, *colon2, *ep;
	int		 dupfd;
	int		 first = 1;

	memset(idx, 0, sizeof(*idx));

	if (lseek(fd, 0, SEEK_SET) == -1) {
		log_warn("lseek %s", STORE_INDEX_NAME);
		return (-1);
	}
	if ((dupfd = dup(fd)) == -1) {
		log_warn("dup %s", STORE_INDEX_NAME);
		return (-1);
	}
	if ((fp = fdopen(dupfd, "r")) == NULL) {
		log_warn("fdopen %s", STORE_INDEX_NAME);
		close(dupfd);
		return (-1);
	}

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (linelen >= STORE_INDEX_LINE_MAX) {
			log_warnx("%s: line too long, index not parsed",
			    STORE_INDEX_NAME);
			goto fail;
		}
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0')
			continue;

		if (first) {
			first = 0;
			if ((colon = strchr(line, ':')) == NULL) {
				log_warnx("malformed index header: %s", line);
				goto fail;
			}
			*colon = '\0';
			if (line[0] < '0' || line[0] > '9') {
				log_warnx("malformed UIDVALIDITY: %s", line);
				goto fail;
			}
			idx->uidvalidity = strtonum(line, 0, UINT32_MAX,
			    &errstr);
			if (errstr != NULL) {
				log_warnx("malformed UIDVALIDITY: %s", line);
				goto fail;
			}

			/* HIGHESTMODSEQ is optional, and absent means 1. */
			if ((colon2 = strchr(colon + 1, ':')) != NULL)
				*colon2 = '\0';

			if (colon[1] < '0' || colon[1] > '9') {
				log_warnx("malformed UIDNEXT: %s", colon + 1);
				goto fail;
			}
			idx->uidnext = strtonum(colon + 1, 0, UINT32_MAX,
			    &errstr);
			if (errstr != NULL) {
				log_warnx("malformed UIDNEXT: %s", colon + 1);
				goto fail;
			}

			if (colon2 != NULL) {
				if (colon2[1] < '0' || colon2[1] > '9') {
					log_warnx("malformed HIGHESTMODSEQ: %s",
					    colon2 + 1);
					goto fail;
				}
				idx->highestmodseq = strtonum(colon2 + 1, 0,
				    INDEX_MODSEQ_MAX, &errstr);
				if (errstr != NULL) {
					log_warnx("malformed HIGHESTMODSEQ: %s",
					    colon2 + 1);
					goto fail;
				}
			} else
				idx->highestmodseq = 1;
			continue;
		}

		if (line[0] >= '0' && line[0] <= '9') {
			errno = 0;
			uid = strtoul(line, &ep, 10);
			if (*ep == ':' && errno == 0) {
				if (uid <= lastuid || uid >= idx->uidnext) {
					log_warnx("%s: UIDs out of order, "
					    "index not parsed",
					    STORE_INDEX_NAME);
					goto fail;
				}
				lastuid = uid;
			}
		}

		if (index_lines_grow(idx) == -1)
			goto fail;
		if ((idx->lines[idx->nlines] = strdup(line)) == NULL) {
			log_warn("strdup index line");
			goto fail;
		}
		idx->nlines++;
	}
	if (ferror(fp)) {
		log_warn("getline %s", STORE_INDEX_NAME);
		goto fail;
	}
	free(line);
	fclose(fp);

	if (first) {
		idx->uidvalidity = uidvalidity_next();
		idx->uidnext = 1;
		idx->highestmodseq = 1;
		idx->fresh = 1;		/* The caller must save it. */
	}

	return (0);

fail:
	free(line);
	index_free(idx);
	fclose(fp);
	return (-1);
}

int
index_parse_line(const char *line, struct index_rec *rec)
{
	unsigned long	 parsed;
	const char	*p, *q, *r, *errstr;
	char		*ep;

	memset(rec, 0, sizeof(*rec));

	if (line[0] < '0' || line[0] > '9') {
		log_warnx("corrupt index line (UID field is not a decimal "
		    "number)");
		return (-1);
	}
	errno = 0;
	parsed = strtoul(line, &ep, 10);
	if (*ep != ':' || errno != 0 || parsed > UINT32_MAX) {
		log_warnx("corrupt index line: %s", line);
		return (-1);
	}
	rec->uid = (uint32_t)parsed;
	p = ep + 1;
	if ((q = strchr(p, ':')) == NULL) {
		log_warnx("corrupt index line: %s", line);
		return (-1);
	}
	if ((size_t)(q - p) >= sizeof(rec->basename)) {
		log_warnx("basename too long in index line");
		return (-1);
	}
	memcpy(rec->basename, p, (size_t)(q - p));
	rec->basename[q - p] = '\0';
	if (!index_basename_valid(rec->basename)) {
		log_warnx("index line uid %u: unsafe basename", rec->uid);
		return (-1);
	}

	p = q + 1;
	if ((r = strchr(p, ':')) != NULL) {
		/* The keywords end at the MODSEQ separator. */
		if ((size_t)(r - p) >= sizeof(rec->keywords)) {
			log_warnx("keywords too long in index line");
			return (-1);
		}
		memcpy(rec->keywords, p, (size_t)(r - p));
		rec->keywords[r - p] = '\0';

		if (r[1] < '0' || r[1] > '9') {
			log_warnx("malformed per-message MODSEQ in index "
			    "line: %s", line);
			return (-1);
		}
		rec->modseq = strtonum(r + 1, 0, INDEX_MODSEQ_MAX, &errstr);
		if (errstr != NULL) {
			log_warnx("malformed per-message MODSEQ in index "
			    "line: %s", line);
			return (-1);
		}
	} else {
		/* A line from before CONDSTORE. */
		if (strlcpy(rec->keywords, p, sizeof(rec->keywords)) >=
		    sizeof(rec->keywords)) {
			log_warnx("keywords too long in index line");
			return (-1);
		}
		rec->modseq = 1;
	}

	return (0);
}

/*
 * The value of "*" is the highest UID present.
 */
uint32_t
index_max_uid(struct mbox_index *idx)
{
	struct index_rec	 rec;

	if (idx->nlines == 0)
		return (0);

	if (index_parse_line(idx->lines[idx->nlines - 1], &rec) == -1)
		return (0);
	return (rec.uid);
}

uint32_t
seqset_resolve(const struct seq_range *ranges, uint32_t nranges,
    uint32_t max, int clamp_hi, struct seq_range resolved[SEQSET_MAX_RANGES])
{
	uint32_t	i, n = 0, lo, hi, tmp;

	for (i = 0; i < nranges; i++) {
		lo = ranges[i].lo_is_star ? max : ranges[i].lo;
		hi = ranges[i].hi_is_star ? max : ranges[i].hi;
		if (lo > hi) {
			tmp = lo;

			lo = hi;
			hi = tmp;
		}
		if (lo < 1)
			lo = 1;
		if (clamp_hi && hi > max)
			hi = max;
		resolved[n].lo = lo;
		resolved[n].hi = hi;
		resolved[n].lo_is_star = resolved[n].hi_is_star = 0;
		n++;
	}
	return (n);
}

int
seqset_contains(const struct seq_range *resolved, uint32_t nresolved,
    uint32_t val)
{
	uint32_t	i;

	for (i = 0; i < nresolved; i++) {
		if (val >= resolved[i].lo && val <= resolved[i].hi)
			return (1);
	}
	return (0);
}

uint32_t
seqset_max_hi(const struct seq_range *resolved, uint32_t nresolved)
{
	uint32_t	i, max = 0;

	for (i = 0; i < nresolved; i++) {
		if (resolved[i].hi > max)
			max = resolved[i].hi;
	}
	return (max);
}

/*
 * A UID command's set is in UID space.
 */
enum seqset_pos
seqset_position(const struct seq_range *resolved, uint32_t nresolved,
    uint32_t max_hi, int by_uid, uint32_t uid, uint32_t seqno)
{
	uint32_t	val = by_uid ? uid : seqno;

	if (val > max_hi)
		return (SEQSET_PAST_END);
	if (!seqset_contains(resolved, nresolved, val))
		return (SEQSET_SKIP);
	return (SEQSET_MATCH);
}

void
send_vanished_range(const struct mbox_index *idx, uint32_t lo, uint32_t hi,
    struct store_session *ss)
{
	struct imsg_mbox_select_vanished	van;
	struct index_rec			rec;
	uint32_t				want, i;

	if (hi < lo)
		return;

	want = lo;
	for (i = 0; i < idx->nlines && want <= hi; i++) {
		if (index_parse_line(idx->lines[i], &rec) == -1)
			continue;
		if (rec.uid < want)
			continue;
		if (rec.uid > hi)
			break;

		if (rec.uid > want) {
			memset(&van, 0, sizeof(van));
			van.uid_lo = want;
			van.uid_hi = rec.uid - 1;
			if (imsg_compose(&ss->iev.ibuf,
			    IMSG_MBOX_SELECT_VANISHED, 0, 0, -1, &van,
			    sizeof(van)) == -1)
				log_warn("session %u: imsg_compose "
				    "IMSG_MBOX_SELECT_VANISHED", ss->id);
		}

		/* UINT32_MAX + 1 would wrap to 0. */
		if (rec.uid == UINT32_MAX)
			return;
		want = rec.uid + 1;
	}

	if (want <= hi) {
		memset(&van, 0, sizeof(van));
		van.uid_lo = want;
		van.uid_hi = hi;
		if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_SELECT_VANISHED, 0, 0,
		    -1, &van, sizeof(van)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_SELECT_VANISHED", ss->id);
	}
}

static int
index_has_basename(struct mbox_index *idx, const char *basename)
{
	const char	*p, *basefield, *end;
	size_t		i, len;

	for (i = 0; i < idx->nlines; i++) {
		p = idx->lines[i];

		if ((basefield = strchr(p, ':')) == NULL)
			continue;
		basefield++;
		end = strchr(basefield, ':');
		len = (end != NULL) ? (size_t)(end - basefield) :
		    strlen(basefield);
		if (strlen(basename) == len &&
		    strncmp(basefield, basename, len) == 0)
			return (1);
	}
	return (0);
}

int
index_append(struct mbox_index *idx, uint32_t uid, const char *basename)
{
	char	line[STORE_INDEX_LINE_MAX];
	int	len;

	/* UID 0 is invalid, so refuse rather than wrap. */
	if (uid == 0) {
		log_warnx("index entry with UID 0, refused");
		return (-1);
	}

	if (strpbrk(basename, ":\r\n") != NULL) {
		log_warnx("index entry %s: unsafe basename", basename);
		return (-1);
	}

	idx->highestmodseq++;

	len = snprintf(line, sizeof(line), "%u:%s::%llu", uid, basename,
	    (unsigned long long)idx->highestmodseq);
	if (len < 0 || (size_t)len >= sizeof(line)) {
		log_warnx("index line too long for %s", basename);
		return (-1);
	}

	if (index_lines_grow(idx) == -1)
		return (-1);
	if ((idx->lines[idx->nlines] = strdup(line)) == NULL) {
		log_warn("strdup index line");
		return (-1);
	}
	idx->nlines++;
	return (0);
}

/*
 * Readers never see a torn file, thanks to rename(2).
 */
int
index_save(int dfd, const struct mbox_index *idx)
{
	size_t	 i;
	FILE	*fp;
	int	 fd, serrno;

	if (unlinkat(dfd, STORE_INDEX_TMP_NAME, 0) == -1 &&
	    errno != ENOENT) {
		log_warn("unlink %s", STORE_INDEX_TMP_NAME);
		return (-1);
	}
	/* O_EXCL never follows a planted symlink. */
	if ((fd = openat(dfd, STORE_INDEX_TMP_NAME,
	    O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		log_warn("open %s", STORE_INDEX_TMP_NAME);
		return (-1);
	}
	if ((fp = fdopen(fd, "w")) == NULL) {
		log_warn("fdopen %s", STORE_INDEX_TMP_NAME);
		close(fd);
		return (-1);
	}

	if (fprintf(fp, "%u:%u:%llu\n", idx->uidvalidity, idx->uidnext,
	    (unsigned long long)idx->highestmodseq) < 0) {
		log_warnx("write index header failed");
		goto fail;
	}
	for (i = 0; i < idx->nlines; i++) {
		if (fprintf(fp, "%s\n", idx->lines[i]) < 0) {
			log_warnx("write index line failed");
			goto fail;
		}
	}
	if (fflush(fp) != 0) {
		log_warn("fflush %s", STORE_INDEX_TMP_NAME);
		goto fail;
	}
	if (fsync(fileno(fp)) == -1) {
		log_warn("fsync %s", STORE_INDEX_TMP_NAME);
		goto fail;
	}
	if (fclose(fp) != 0) {
		log_warn("fclose %s", STORE_INDEX_TMP_NAME);
		return (-1);
	}

	if (renameat(dfd, STORE_INDEX_TMP_NAME, dfd,
	    STORE_INDEX_NAME) == -1) {
		log_warn("rename %s -> %s", STORE_INDEX_TMP_NAME,
		    STORE_INDEX_NAME);
		return (-1);
	}

	/* Sync the directory, so the rename survives a crash. */
	if (fsync(dfd) == -1)
		log_warn("fsync mailbox directory (continuing)");
	return (0);

fail:
	/* Keep errno, as ENOSPC becomes OVERQUOTA. */
	serrno = errno;
	fclose(fp);
	errno = serrno;
	return (-1);
}

void
index_free(struct mbox_index *idx)
{
	size_t	i;

	for (i = 0; i < idx->nlines; i++)
		free(idx->lines[i]);
	free(idx->lines);
	memset(idx, 0, sizeof(*idx));
}

/*
 * Here "$" means the result saved before this SELECT.
 */
void
qresync_send_resync(const struct imsg_mbox_select *req,
    const struct seq_range *ranges, uint32_t nranges,
    struct mbox_index *idx, struct store_session *ss)
{
	struct index_rec		rec;
	struct imsg_mbox_fetch_meta	meta;
	struct imsgev			*iev = &ss->iev;
	struct seq_range		resolved[2 * SEQSET_MAX_RANGES];
	char				suffix[64];
	off_t				size;
	uint32_t			nresolved, max_hi, i, used;

	if (req->qresync_has_uids) {
		used = nranges > 0 && SEQ_RANGE_SAVED(&ranges[nranges - 1]);
		nresolved = seqset_resolve(ranges, nranges - used,
		    index_max_uid(idx), 0, resolved);
		if (used) {
			memcpy(resolved + nresolved, ss->saved,
			    ss->nsaved * sizeof(*resolved));
			nresolved += ss->nsaved;
		}
	} else {
		/* No known-uids means every UID below uidnext. */
		if (idx->uidnext <= 1)
			return;
		resolved[0].lo = 1;
		resolved[0].hi = idx->uidnext - 1;
		resolved[0].lo_is_star = resolved[0].hi_is_star = 0;
		nresolved = 1;
	}

	for (i = 0; i < nresolved; i++)
		send_vanished_range(idx, resolved[i].lo, resolved[i].hi, ss);

	max_hi = seqset_max_hi(resolved, nresolved);
	for (i = 0; i < idx->nlines; i++) {
		if (index_parse_line(idx->lines[i], &rec) == -1)
			/* Corrupt, and already logged. */
			continue;
		if (rec.uid > max_hi)
			break;
		if (!seqset_contains(resolved, nresolved, rec.uid))
			continue;

		if (rec.modseq > req->qresync_modseq) {
			memset(&meta, 0, sizeof(meta));
			meta.seqno = i + 1;
			meta.uid = rec.uid;
			meta.modseq = rec.modseq;
			if (locate_message_file(&ss->cur_snap,
			    ss->mailbox_dir_fd, rec.basename, &size, suffix,
			    sizeof(suffix)) == 0) {
				build_flags_string(suffix, rec.keywords,
				    meta.flags, sizeof(meta.flags));
			}
			if (imsg_compose(&iev->ibuf, IMSG_MBOX_FETCH_META, 0,
			    0, -1, &meta, sizeof(meta)) == -1)
				log_warn("session %u: imsg_compose "
				    "IMSG_MBOX_FETCH_META (qresync)",
				    ss->id);
		}
	}
}

/*
 * Open after locking, so fd names the current inode.
 */
int
index_lock_acquire(int dfd, struct index_lock *il, int op)
{
	int	busy;

	il->lockfd = -1;
	il->fd = -1;

	if ((il->lockfd = openat(dfd, STORE_INDEX_LOCK_NAME,
	    O_RDWR | O_CREAT, 0600)) == -1) {
		log_warn("open %s", STORE_INDEX_LOCK_NAME);
		return (INDEX_LOCK_ERR);
	}
	if (flock(il->lockfd, op) == -1) {
		busy = (op & LOCK_NB) && errno == EWOULDBLOCK;
		if (!busy)
			log_warn("flock %s", STORE_INDEX_LOCK_NAME);
		close(il->lockfd);
		il->lockfd = -1;
		return (busy ? INDEX_LOCK_BUSY : INDEX_LOCK_ERR);
	}
	if ((il->fd = openat(dfd, STORE_INDEX_NAME, O_RDWR | O_CREAT,
	    0600)) == -1) {
		log_warn("open %s", STORE_INDEX_NAME);
		flock(il->lockfd, LOCK_UN);
		close(il->lockfd);
		il->lockfd = -1;
		return (INDEX_LOCK_ERR);
	}
	return (INDEX_LOCK_OK);
}

void
index_lock_release(struct index_lock *il)
{
	if (il->fd != -1) {
		close(il->fd);
		il->fd = -1;
	}
	/* Unlock last, so nobody locks while fd is open. */
	if (il->lockfd != -1) {
		flock(il->lockfd, LOCK_UN);
		close(il->lockfd);
		il->lockfd = -1;
	}
}

/*
 * UIDVALIDITY must grow, so time is only a floor.
 */
static uint32_t
uidvalidity_next(void)
{
	struct stat	 st;
	const char	*path, *errstr;
	uint32_t	 uvfloor = 0, val;
	ssize_t		 n;
	time_t		 now;
	char		 buf[32];
	int		 fd, writeback = 1;

	path = STORE_UIDVALIDITY_NAME;

	now = time(NULL);
	val = (now > 0 && (uintmax_t)now <= UINT32_MAX) ? (uint32_t)now : 0;

	if ((fd = openat(maildir_root_fd, path, O_RDWR | O_CREAT,
	    0600)) == -1) {
		log_warn("open %s, using a bare timestamp", path);
		return (val != 0 ? val : 1);
	}
	if (flock(fd, LOCK_EX) == -1) {
		log_warn("flock %s, using a bare timestamp", path);
		close(fd);
		return (val != 0 ? val : 1);
	}

	if (fstat(fd, &st) == 0 && st.st_size > 0) {
		if ((n = read(fd, buf, sizeof(buf) - 1)) <= 0) {
			log_warn("read %s (UIDVALIDITY floor)", path);
			writeback = 0;
		} else {
			buf[n] = '\0';
			buf[strcspn(buf, "\r\n")] = '\0';
			errstr = "not a decimal number";
			if (buf[0] >= '0' && buf[0] <= '9')
				uvfloor = strtonum(buf, 0, UINT32_MAX, &errstr);
			if (errstr != NULL) {
				log_warnx("%s: no usable UIDVALIDITY floor "
				    "(%s), using a bare timestamp", path, buf);
				writeback = 0;
				uvfloor = 0;
			}
		}
	}

	if (writeback) {
		if (val <= uvfloor) {
			if (uvfloor == UINT32_MAX) {
				log_warnx("UIDVALIDITY floor is exhausted "
				    "(%u); reusing it", uvfloor);
				val = UINT32_MAX;
				writeback = 0;
			} else
				val = uvfloor + 1;
		}
	} else if (val == 0)
		val = 1;		/* Neither clock nor floor is usable. */

	if (writeback) {
		n = snprintf(buf, sizeof(buf), "%u\n", val);
		if (n < 0 || (size_t)n >= sizeof(buf) ||
		    lseek(fd, 0, SEEK_SET) == -1 ||
		    ftruncate(fd, 0) == -1 ||
		    write(fd, buf, (size_t)n) != n)
			log_warn("%s: UIDVALIDITY floor not recorded", path);
	}

	log_debug("UIDVALIDITY floor %u in %s, issued %u%s", uvfloor, path, val,
	    writeback ? "" : " (floor kept)");

	close(fd);			/* This releases the flock(2). */
	return (val);
}

/*
 * Messages need CRLF, but mail.maildir(8) writes bare LF.
 */
static int
to_crlf(int dfd, const char *dir, const char *name)
{
	struct stat	 st;
	ssize_t		 n;
	size_t		 i, o, w;
	char		 src[PATH_MAX], tmp[PATH_MAX];
	char		*in = NULL, *out;
	int		 ifd = -1, ofd = -1, made = 0, cr = 0, changed = 0;
	int		 rc = -1, srclen, tmplen;

	srclen = snprintf(src, sizeof(src), "%s/%s", dir, name);
	tmplen = snprintf(tmp, sizeof(tmp), "tmp/%s.crlf", name);
	if (srclen < 0 || (size_t)srclen >= sizeof(src) ||
	    tmplen < 0 || (size_t)tmplen >= sizeof(tmp)) {
		log_warnx("%s/%s: name too long for CRLF, indexed as it is",
		    dir, name);
		return (-1);
	}
	ifd = openat(dfd, src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	if (ifd == -1 || fstat(ifd, &st) == -1)
		goto fail;
	if (!S_ISREG(st.st_mode)) {
		log_warnx("%s: not a regular file, indexed as it is", src);
		goto done;
	}
	if ((in = malloc((size_t)3 * STORE_READ_BLOCK)) == NULL)
		goto fail;
	out = in + STORE_READ_BLOCK;
	ofd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (ofd == -1 && errno == EEXIST && unlinkat(dfd, tmp, 0) == 0)
		ofd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (ofd == -1)
		goto fail;
	made = 1;

	for (;;) {
		if ((n = read(ifd, in, STORE_READ_BLOCK)) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (n == 0)
			break;
		for (i = 0, o = 0; i < (size_t)n; i++) {
			if (in[i] == '\n' && !cr) {
				out[o++] = '\r';
				changed = 1;
			}
			cr = in[i] == '\r';
			out[o++] = in[i];
		}
		for (w = 0; w < o; w += (size_t)n) {
			while ((n = write(ofd, out + w, o - w)) == -1 &&
			    errno == EINTR)
				;
			if (n == -1)
				goto fail;
		}
	}

	if (changed) {
		if (fsync(ofd) == -1)
			goto fail;
		n = close(ofd);
		ofd = -1;
		if (n == -1 || renameat(dfd, tmp, dfd, src) == -1)
			goto fail;
		made = 0;
		log_debug("%s: bare LF made CRLF", src);
	}
	rc = changed;
	goto done;

fail:
	log_warn("%s to CRLF, indexed as it is", src);
done:
	if (ifd != -1)
		close(ifd);
	if (ofd != -1)
		close(ofd);
	if (made)
		unlinkat(dfd, tmp, 0);
	free(in);
	return (rc);
}

static void
new_to_cur(int dfd, const char *name)
{
	struct stat	st;
	char		from[PATH_MAX], to[PATH_MAX];
	int		fromlen, tolen;

	fromlen = snprintf(from, sizeof(from), "new/%s", name);
	tolen = snprintf(to, sizeof(to), "cur/%s", name);
	if (fromlen < 0 || (size_t)fromlen >= sizeof(from) ||
	    tolen < 0 || (size_t)tolen >= sizeof(to)) {
		log_warnx("new/%s: name too long to move to cur/", name);
		return;
	}
	if (fstatat(dfd, to, &st, AT_SYMLINK_NOFOLLOW) == 0) {
		log_warnx("%s: not moved, %s already exists", from, to);
		return;
	}
	if (errno != ENOENT || renameat(dfd, from, dfd, to) == -1)
		log_warn("moving %s to cur/", from);
}

static int
index_scan_new(int dfd, struct mbox_index *idx, int mutate)
{
	struct dirent	*de;
	const char	*info;
	DIR		*dp;
	int		 added = 0, converted = 0;

	if ((dp = opendirat(dfd, "new")) == NULL) {
		if (errno == ENOENT)
			/* A never-used mailbox may lack new/. */
			return (0);
		log_warn("opendir new");
		if (mutate)
			index_free(idx);
		return (-1);
	}
	while ((de = readdir(dp)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		/* A ":2," name belongs in cur/, indexed there. */
		if (strpbrk(de->d_name, "\r\n") == NULL &&
		    (info = strchr(de->d_name, ':')) != NULL &&
		    strncmp(info, ":2,", 3) == 0) {
			if (!mutate) {
				closedir(dp);
				return (1);
			}
			new_to_cur(dfd, de->d_name);
			continue;
		}
		/* A colon or newline would corrupt the index line. */
		if (strpbrk(de->d_name, ":\r\n") != NULL) {
			if (mutate)
				log_warnx("new/%s: unsafe name, skipped",
				    de->d_name);
			continue;
		}
		if (index_has_basename(idx, de->d_name))
			continue;
		if (!mutate) {
			closedir(dp);
			return (1);
		}
		/* Convert first, as content under a UID is fixed. */
		if (to_crlf(dfd, "new", de->d_name) == 1)
			converted = 1;
		if (index_append(idx, idx->uidnext, de->d_name) == -1) {
			closedir(dp);
			index_free(idx);
			return (-1);
		}
		idx->uidnext++;
		added = 1;
	}
	if (converted && fsync(dirfd(dp)) == -1)
		log_warn("fsync new");
	closedir(dp);
	return (added);
}

static size_t
base_slot(const struct base_set *bs, const char *s, size_t len)
{
	uint32_t	h = 2166136261U;	/* FNV-1a offset basis. */
	size_t		i, k;

	for (i = 0; i < len; i++)
		h = (h ^ (unsigned char)s[i]) * 16777619U;
	for (k = h & bs->mask; bs->name[k] != NULL; k = (k + 1) & bs->mask)
		if (bs->len[k] == len && memcmp(bs->name[k], s, len) == 0)
			break;
	return (k);
}

static int
name_cmp(const void *a, const void *b)
{
	return (strcmp(*(char * const *)a, *(char * const *)b));
}

static int
index_scan_cur(int dfd, struct mbox_index *idx, int mutate)
{
	struct base_set	 bs = { NULL, NULL, 0 };
	struct dirent	*de;
	struct stat	 st;
	const char	*p, *prev = NULL;
	size_t		 nfound = 0, cap = 0, size = 1, i, k, len;
	size_t		 prevlen = 0, added = 0;
	char		**found = NULL, **grown, *info, *name;
	char		 base[NAME_MAX + 1], from[PATH_MAX], to[PATH_MAX];
	DIR		*dp = NULL;
	int		 synced = 0, rv = -1, fromlen, tolen;

	while (size < 2 * idx->nlines + 1)
		size <<= 1;
	bs.mask = size - 1;
	if ((bs.name = calloc(size, sizeof(*bs.name))) == NULL ||
	    (bs.len = calloc(size, sizeof(*bs.len))) == NULL) {
		log_warn("scanning cur");
		goto done;
	}
	for (i = 0; i < idx->nlines; i++) {
		if ((p = strchr(idx->lines[i], ':')) == NULL)
			continue;
		len = strcspn(++p, ":");
		k = base_slot(&bs, p, len);
		bs.name[k] = p;
		bs.len[k] = len;
	}

	if ((dp = opendirat(dfd, "cur")) == NULL) {
		if (errno == ENOENT)
			rv = 0;
		else
			log_warn("opendir cur");
		goto done;
	}
	while ((de = readdir(dp)) != NULL) {
		if (de->d_name[0] == '.' ||
		    strpbrk(de->d_name, "\r\n") != NULL)
			continue;
		len = strcspn(de->d_name, ":");
		if (bs.name[base_slot(&bs, de->d_name, len)] != NULL)
			continue;
		info = de->d_name[len] == ':' ? de->d_name + len : NULL;
		if (len >= sizeof(base) ||
		    (info != NULL && strncmp(info, ":2,", 3) != 0)) {
			if (mutate)
				log_warnx("cur/%s: not indexed, not a maildir "
				    "name", de->d_name);
			continue;
		}
		/* Probably left by an EXPUNGE whose unlink(2) failed. */
		if (info != NULL && !idx->fresh &&
		    strchr(info + 3, 'T') != NULL) {
			if (mutate)
				log_warnx("cur/%s: not indexed, flagged "
				    "deleted", de->d_name);
			continue;
		}
		memcpy(base, de->d_name, len);
		base[len] = '\0';
		if (!index_basename_valid(base))
			continue;
		if (!mutate) {
			rv = 1;
			goto done;
		}
		if (nfound == cap) {
			cap = cap != 0 ? cap * 2 : 64;
			if ((grown = reallocarray(found, cap,
			    sizeof(*found))) == NULL) {
				log_warn("scanning cur");
				goto done;
			}
			found = grown;
		}
		if ((found[nfound] = strdup(de->d_name)) == NULL) {
			log_warn("scanning cur");
			goto done;
		}
		nfound++;
	}
	if (nfound > 1)
		qsort(found, nfound, sizeof(*found), name_cmp);

	for (i = 0; i < nfound; i++) {
		name = found[i];
		len = strcspn(name, ":");
		if (prev != NULL && len == prevlen &&
		    memcmp(prev, name, len) == 0) {
			log_warnx("cur/%s: not indexed, another file has its "
			    "base name", name);
			continue;
		}
		if (name[len] == '\0') {
			fromlen = snprintf(from, sizeof(from), "cur/%s", name);
			tolen = snprintf(to, sizeof(to), "cur/%s:2,", name);
			if (fromlen < 0 || (size_t)fromlen >= sizeof(from) ||
			    tolen < 0 || (size_t)tolen >= sizeof(to) ||
			    fstatat(dfd, to, &st, AT_SYMLINK_NOFOLLOW) == 0) {
				log_warnx("cur/%s: not indexed, cannot add "
				    "\":2,\"", name);
				continue;
			}
			if (errno != ENOENT ||
			    renameat(dfd, from, dfd, to) == -1) {
				log_warn("cur/%s: not indexed", name);
				continue;
			}
			synced = 1;
			name = to + strlen("cur/");
		}
		prev = found[i];
		prevlen = len;
		/* Convert first, as content under a UID is fixed. */
		if (to_crlf(dfd, "cur", name) == 1)
			synced = 1;
		memcpy(base, name, len);
		base[len] = '\0';
		if (index_append(idx, idx->uidnext, base) == -1)
			goto done;
		idx->uidnext++;
		added++;
	}
	if (synced && fsync(dirfd(dp)) == -1)
		log_warn("fsync cur");
	if (added > 0)
		log_info("indexed %zu file(s) found in cur/", added);
	rv = added > 0;

done:
	if (dp != NULL)
		closedir(dp);
	for (i = 0; i < nfound; i++)
		free(found[i]);
	free(found);
	free(bs.name);
	free(bs.len);
	if (rv == -1 && mutate)
		index_free(idx);
	return (rv);
}

static int
index_scan(int dfd, struct mbox_index *idx, int mutate)
{
	int	in_new, in_cur;

	if ((in_new = index_scan_new(dfd, idx, mutate)) == -1)
		return (-1);
	if (in_new && !mutate)
		return (1);
	if ((in_cur = index_scan_cur(dfd, idx, mutate)) == -1)
		return (-1);
	return (in_new || in_cur);
}

int
refresh_index(int dfd, struct mbox_index *idx, int fd)
{
	int	added, serrno;

	if (index_load(fd, idx) == -1)
		return (-1);

	if ((added = index_scan(dfd, idx, 1)) == -1)
		return (-1);	/* The scan has freed idx. */

	/* A fresh UIDVALIDITY must still be saved. */
	if (!added && !idx->fresh)
		return (0);

	if (index_save(dfd, idx) == -1) {
		serrno = errno;
		index_free(idx);
		errno = serrno;
		return (-1);
	}
	return (0);
}

void
idle_probe_reset(struct store_session *ss)
{
	ss->idle_probe.valid = 0;
}

void
idle_baseline_reset(struct store_session *ss)
{
	struct store_idle_baseline	*base = &ss->idle_baseline;

	free(base->uids);
	base->uids = NULL;
	base->n = 0;
	base->modseq = 0;
	base->ghosts = 0;
	base->valid = 0;
}

static size_t
uid_find(const uint32_t *list, size_t n, uint32_t uid)
{
	size_t	lo = 0, hi = n, mid;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (list[mid] < uid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return ((lo < n && list[lo] == uid) ? lo : n);
}

/*
 * Report it once, then drop it from the baseline.
 */
int
send_expunged(struct store_session *ss, uint32_t seqno, uint32_t uid)
{
	struct store_idle_baseline	*base = &ss->idle_baseline;
	struct imsg_mbox_expunged	 expunged;
	size_t				 at;

	at = uid_find(base->uids, base->n, uid);
	memset(&expunged, 0, sizeof(expunged));
	expunged.seqno = at < base->n ? (uint32_t)at + 1 : seqno;
	expunged.uid = uid;
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_EXPUNGED, 0, 0, -1, &expunged,
	    sizeof(expunged)) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_EXPUNGED",
		    ss->id);
		return (-1);
	}
	if (at < base->n) {
		memmove(&base->uids[at], &base->uids[at + 1],
		    (base->n - at - 1) * sizeof(*base->uids));
		base->n--;
	}
	return (0);
}

uint32_t
view_seqno(const struct store_session *ss, uint32_t uid, uint32_t fallback)
{
	const struct store_idle_baseline	*base = &ss->idle_baseline;
	size_t					 at;

	if (!base->valid)
		return (fallback);
	at = uid_find(base->uids, base->n, uid);
	return (at < base->n ? (uint32_t)at + 1 : fallback);
}

/*
 * Turn a sequence set into UIDs through the view.  Set *by_uid if
 * converted.
 */
void
view_resolve(const struct store_session *ss, const struct seq_range *in,
    uint32_t nin, struct seq_range *out, uint32_t *nout, int *by_uid)
{
	const struct store_idle_baseline	*base = &ss->idle_baseline;
	uint32_t				 i, lo, hi, tmp, n = 0;

	if (*by_uid || !base->valid) {
		for (i = 0; i < nin; i++)
			out[i] = in[i];
		*nout = nin;
		return;
	}
	for (i = 0; i < nin; i++) {
		lo = in[i].lo_is_star ? (uint32_t)base->n : in[i].lo;
		hi = in[i].hi_is_star ? (uint32_t)base->n : in[i].hi;
		if (lo > hi) {
			tmp = lo;
			lo = hi;
			hi = tmp;
		}
		if (lo < 1)
			lo = 1;
		if (hi > base->n)
			hi = (uint32_t)base->n;
		if (lo > hi)
			continue;
		memset(&out[n], 0, sizeof(out[n]));
		out[n].lo = base->uids[lo - 1];
		out[n].hi = base->uids[hi - 1];
		n++;
	}
	*nout = n;
	*by_uid = 1;
}

/*
 * Resolve as view_resolve(), appending a last "$" as UIDs.  Return -2 if
 * the set stays in sequence numbers, or -1 past the cap.
 */
int
saved_resolve(const struct store_session *ss, const struct seq_range *in,
    uint32_t nin, struct seq_range *out, uint32_t *nout, int *by_uid,
    int *used)
{
	int	u;

	u = *used = nin > 0 && SEQ_RANGE_SAVED(&in[nin - 1]);
	if (u)
		nin--;
	view_resolve(ss, in, nin, out, nout, by_uid);
	if (!u)
		return (0);
	if (*by_uid == 0 && nin > 0)
		return (-2);
	*by_uid = 1;
	if (*nout + ss->nsaved > SEQSET_MAX_RANGES)
		return (-1);
	memcpy(out + *nout, ss->saved, ss->nsaved * sizeof(*out));
	*nout += ss->nsaved;
	return (0);
}

/*
 * Return 1 if the set names an unreported expunge.
 */
int
view_names_ghost(const struct store_session *ss, const struct mbox_index *idx,
    const struct seq_range *uids, uint32_t nuids)
{
	const struct store_idle_baseline	*base = &ss->idle_baseline;
	struct index_rec			 rec;
	size_t					 i, j = 0;

	if (!base->valid || base->ghosts == 0)
		return (0);
	memset(&rec, 0, sizeof(rec));
	for (i = 0; i < base->n; i++) {
		if (!seqset_contains(uids, nuids, base->uids[i]))
			continue;
		for (; j < idx->nlines; j++)
			if (index_parse_line(idx->lines[j], &rec) == 0 &&
			    rec.uid >= base->uids[i])
				break;
		if (j == idx->nlines || rec.uid != base->uids[i])
			return (1);
	}
	return (0);
}

/*
 * Each EXPUNGE renumbers the messages above it.
 */
static size_t
view_merge(const uint32_t *old, size_t oldn, const uint32_t *cur,
    size_t curn, int expunge_ok, uint32_t *view, size_t *viewn,
    struct store_session *ss)
{
	struct imsg_mbox_expunged	 item;
	size_t				 i = 0, j = 0, n = 0, gone = 0;

	while (i < oldn || j < curn) {
		if (j < curn && (i == oldn || cur[j] < old[i])) {
			view[n++] = cur[j++];
			continue;
		}
		if (j < curn && cur[j] == old[i]) {
			view[n++] = old[i++];
			j++;
			continue;
		}
		if (!expunge_ok) {
			view[n++] = old[i++];
			continue;
		}
		memset(&item, 0, sizeof(item));
		item.seqno = (uint32_t)n + 1;
		item.uid = old[i++];
		gone++;
		if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_VIEW_EXPUNGE, 0, 0,
		    -1, &item, sizeof(item)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_VIEW_EXPUNGE", ss->id);
	}
	*viewn = n;
	return (gone);
}

/*
 * Report flag changes as FETCH responses with the UID.
 */
static size_t
view_send_flag_fetches(const struct mbox_index *idx, const uint32_t *old,
    size_t oldn, uint64_t since, const uint32_t *view, size_t viewn,
    struct store_session *ss)
{
	struct imsgev			*iev = &ss->iev;
	struct imsg_mbox_fetch_meta	 meta;
	struct index_rec		 rec;
	char				 suffix[64];
	off_t				 size;
	size_t				 i, j = 0, sent = 0;

	for (i = 0; i < idx->nlines; i++) {
		if (index_parse_line(idx->lines[i], &rec) == -1)
			continue;	/* Malformed, so skip it. */
		if (rec.modseq <= since)
			continue;
		while (j < oldn && old[j] < rec.uid)
			j++;
		if (j == oldn || old[j] != rec.uid)
			continue;	/* New, so EXISTS covers it. */
		if (locate_message_file(&ss->cur_snap, ss->mailbox_dir_fd,
		    rec.basename, &size, suffix, sizeof(suffix)) == -1) {
			log_warnx("session %u: message %s (uid %u) indexed "
			    "but missing on disk, not pushed",
			    ss->id, rec.basename, rec.uid);
			continue;
		}
		memset(&meta, 0, sizeof(meta));
		meta.seqno = (uint32_t)uid_find(view, viewn, rec.uid) + 1;
		meta.uid = rec.uid;
		meta.modseq = rec.modseq;
		build_flags_string(suffix, rec.keywords, meta.flags,
		    sizeof(meta.flags));
		sent++;
		if (imsg_compose(&iev->ibuf, IMSG_MBOX_VIEW_FETCH, 0, 0, -1,
		    &meta, sizeof(meta)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_VIEW_FETCH", ss->id);
	}
	return (sent);
}

static int
idle_probe_unchanged(struct store_session *ss)
{
	struct store_idle_probe	*probe = &ss->idle_probe;
	struct stat		 dst, nst;
	int			 same;

	if (fstatat(ss->mailbox_dir_fd, ".", &dst, 0) == -1) {
		probe->valid = 0;
		return (0);
	}
	if (fstatat(ss->mailbox_dir_fd, "new", &nst, 0) == -1)
		/* An absent new/ is a stable state. */
		memset(&nst, 0, sizeof(nst));

	same = probe->valid &&
	    dst.st_ino == probe->dir_ino &&
	    nst.st_ino == probe->new_ino &&
	    timespeccmp(&dst.st_mtim, &probe->dir_mtim, ==) &&
	    timespeccmp(&nst.st_mtim, &probe->new_mtim, ==);

	probe->valid = 1;
	probe->dir_ino = dst.st_ino;
	probe->new_ino = nst.st_ino;
	probe->dir_mtim = dst.st_mtim;
	probe->new_mtim = nst.st_mtim;

	return (same);
}

static int
idle_uid_list(const struct mbox_index *idx, uint32_t **listp, size_t *np,
    uint64_t *modseqp)
{
	struct index_rec	 rec;
	uint32_t		*list;
	uint64_t		 modseq = 0;
	size_t			 i, n = 0;

	if ((list = reallocarray(NULL, idx->nlines + 1, sizeof(*list))) ==
	    NULL) {
		log_warn("idle refresh: reallocarray");
		return (-1);
	}
	for (i = 0; i < idx->nlines; i++) {
		if (index_parse_line(idx->lines[i], &rec) == -1)
			continue;
		list[n++] = rec.uid;
		if (rec.modseq > modseq)
			modseq = rec.modseq;
	}

	if (idx->highestmodseq > modseq)
		modseq = idx->highestmodseq;

	*listp = list;
	*np = n;
	*modseqp = modseq;
	return (0);
}

void
idle_baseline_seed(struct store_session *ss, const struct mbox_index *idx)
{
	struct store_idle_baseline	*base = &ss->idle_baseline;
	uint32_t			*list;
	uint64_t			 modseq;
	size_t				 n;

	idle_baseline_reset(ss);
	if (idle_uid_list(idx, &list, &n, &modseq) == -1)
		return;
	base->uids = list;
	base->n = n;
	base->modseq = modseq;
	base->valid = 1;
}

/*
 * Report what changed, sending EXPUNGE only if expunge_ok.
 */
int
view_sync(struct store_session *ss, const struct mbox_index *idx,
    int expunge_ok)
{
	struct imsg_mbox_view_exists	 ve;
	struct store_idle_baseline	*base = &ss->idle_baseline;
	uint32_t			*cur, *view;
	uint64_t			 seen;
	size_t				 curn, viewn, gone;

	if (!base->valid) {
		idle_baseline_seed(ss, idx);
		return (base->valid ? 0 : -1);
	}
	/* Every append and removal raises HIGHESTMODSEQ. */
	if (idx->nlines == base->n && idx->highestmodseq <= base->modseq)
		return (0);
	if (idle_uid_list(idx, &cur, &curn, &seen) == -1)
		return (-1);
	if ((view = reallocarray(NULL, base->n + curn + 1,
	    sizeof(*view))) == NULL) {
		log_warn("session %u: view: reallocarray", ss->id);
		free(cur);
		return (-1);
	}
	gone = view_merge(base->uids, base->n, cur, curn, expunge_ok, view,
	    &viewn, ss);
	(void)view_send_flag_fetches(idx, base->uids, base->n, base->modseq,
	    view, viewn, ss);
	/* EXISTS follows EXPUNGEs too, as in the IDLE example. */
	if (gone > 0 || viewn != base->n) {
		memset(&ve, 0, sizeof(ve));
		ve.exists = (uint32_t)viewn;
		if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_VIEW_EXISTS, 0, 0,
		    -1, &ve, sizeof(ve)) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_VIEW_EXISTS", ss->id);
	}
	free(cur);
	free(base->uids);
	base->uids = view;
	base->n = viewn;
	base->ghosts = viewn - curn;
	if (seen > base->modseq)
		base->modseq = seen;
	return (0);
}

/*
 * Safe unlocked, as the index is only replaced whole.
 */
static int
idle_seed_unlocked(struct store_session *ss)
{
	struct store_idle_baseline	*base = &ss->idle_baseline;
	struct mbox_index		 idx;
	uint32_t			*list;
	uint64_t			 modseq;
	size_t				 n;
	int				 fd;

	if ((fd = openat(ss->mailbox_dir_fd, STORE_INDEX_NAME,
	    O_RDONLY)) == -1) {
		if (errno != ENOENT)
			log_warn("session %u: open %s", ss->id,
			    STORE_INDEX_NAME);
		return (-1);
	}
	if (index_load(fd, &idx) == -1) {
		close(fd);
		return (-1);
	}
	close(fd);
	if (idle_uid_list(&idx, &list, &n, &modseq) == -1) {
		index_free(&idx);
		return (-1);
	}
	index_free(&idx);

	free(base->uids);
	base->uids = list;
	base->n = n;
	base->modseq = modseq;
	base->ghosts = 0;
	base->valid = 1;
	return (0);
}

void
handle_mbox_idle_refresh(struct store_session *ss)
{
	struct store_idle_baseline	*base = &ss->idle_baseline;
	struct imsgev			*iev = &ss->iev;
	struct mbox_index		 idx;
	struct imsg_mbox_idle_refreshed	 reply;
	struct index_lock		 il = INDEX_LOCK_INIT;
	int				 pending = 0, seeded, locked;

	memset(&reply, 0, sizeof(reply));
	if (!ss->mailbox_selected)
		goto send;
	/* A seed adopts what it finds, reporting nothing. */
	seeded = !base->valid;

	if (idle_probe_unchanged(ss)) {
		reply.ok = 1;
		reply.unchanged = 1;
		log_debug("session %u: idle refresh: unchanged (probe: no "
		    "change to . or new/)", ss->id);
		goto send;
	}

	locked = index_lock_acquire(ss->mailbox_dir_fd, &il, LOCK_SH | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		goto busy;
	if (locked == INDEX_LOCK_ERR)
		goto send;
	if (index_load(il.fd, &idx) == -1) {
		index_lock_release(&il);
		goto send;
	}
	if ((pending = index_scan(ss->mailbox_dir_fd, &idx, 0)) == -1) {
		index_free(&idx);
		index_lock_release(&il);
		goto send;
	}
	if (pending || idx.fresh) {
		/* Relock LOCK_EX from scratch rather than upgrade. */
		index_free(&idx);
		index_lock_release(&il);
		locked = index_lock_acquire(ss->mailbox_dir_fd, &il,
		    LOCK_EX | LOCK_NB);
		if (locked == INDEX_LOCK_BUSY)
			goto busy;
		if (locked == INDEX_LOCK_ERR)
			goto send;
		if (refresh_index(ss->mailbox_dir_fd, &idx, il.fd) == -1) {
			index_lock_release(&il);
			goto send;
		}
	}

	if (view_sync(ss, &idx, 1) == 0)
		reply.ok = 1;

	log_debug("session %u: idle refresh: %zu uid(s) in view, "
	    "highestmodseq %llu%s%s", ss->id, base->n,
	    (unsigned long long)idx.highestmodseq,
	    seeded ? " (baseline seeded)" : "",
	    pending ? " (escalated to LOCK_EX, indexed new delivery)" : "");

	index_free(&idx);
	index_lock_release(&il);
	goto send;

busy:
	/* A seed cannot skip, or EXPUNGEs would repeat. */
	reply.busy = 1;
	if (seeded && idle_seed_unlocked(ss) == 0) {
		reply.ok = 1;
		/* Force the next poll to read the index. */
		idle_probe_reset(ss);
	} else if (seeded) {
		idle_baseline_reset(ss);
	}
	log_debug("session %u: idle refresh: index lock busy, %s", ss->id,
	    !seeded ? "skipped this poll" : reply.ok ? "seeded without it" :
	    "next refresh seeds");

send:
	/* The probe has already consumed this change. */
	if (!reply.ok)
		idle_probe_reset(ss);

	if (imsg_compose(&iev->ibuf, IMSG_MBOX_IDLE_REFRESHED, 0, 0, -1,
	    &reply, sizeof(reply)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_IDLE_REFRESHED",
		    ss->id);
}
