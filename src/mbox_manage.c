/*
 * Copyright (c) 2011 Gilles Chehade <gilles@poolp.org>
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/mount.h>
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

/* With no file, every mailbox counts as subscribed. */
struct sublist {
	char	**names;
	size_t	  n;
	size_t	  cap;
	int	  present;
};

static int	 remove_maildir_subtree(int, const char *);
static int	 mbox_root_entry_is_mailbox(const char *, int *);
static void	 sublist_free(struct sublist *);
static int	 sublist_has(const struct sublist *, const char *);
static int	 sublist_add(struct sublist *, const char *);
static void	 sublist_remove(struct sublist *, const char *);
static int	 sublist_load(struct sublist *);
static int	 sublist_save(const struct sublist *);
static int	 subs_lock_acquire(int *);
static void	 subs_lock_release(int);
static int	 subs_materialise(struct sublist *);
static int	 list_item_send(struct store_session *, const char *, int);
static void	 append_reply(struct store_session *,
		    const struct imsg_mbox_appended *);

int
handle_mbox_select(struct imsg_mbox_select *req,
    const struct seq_range *ranges, uint32_t nranges, struct store_session *ss)
{
	struct imsgev			*iev = &ss->iev;
	struct mbox_index		 idx;
	struct imsg_mbox_selected	 reply;
	struct index_lock		 il = INDEX_LOCK_INIT;
	const char			*target;
	int				 dfd, locked;

	memset(&reply, 0, sizeof(reply));

	idle_probe_reset(ss);
	idle_baseline_reset(ss);

	if (mailbox_name_is_inbox(req->mailbox))
		target = "";
	else if (mailbox_name_valid(req->mailbox))
		target = req->mailbox;
	else {
		log_debug("session %u: SELECT %s: invalid mailbox name",
		    ss->id, req->mailbox);
		reply.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}

	if ((dfd = mailbox_open_dir(target)) == -1) {
		reply.error = errno == ENOENT || errno == ENOTDIR ?
		    MBOX_OP_ERR_NO_SUCH_MAILBOX : MBOX_OP_ERR_GENERIC;
		if (reply.error == MBOX_OP_ERR_GENERIC)
			log_warn("session %u: SELECT %s", ss->id,
			    req->mailbox);
		goto send;
	}

	locked = index_lock_acquire(dfd, &il, LOCK_EX | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY) {
		/* Only IDLE resets ran, and repeating them is harmless. */
		close(dfd);
		return (1);
	}
	if (locked == INDEX_LOCK_ERR) {
		close(dfd);
		reply.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (refresh_index(dfd, &idx, il.fd) == -1) {
		reply.error = errno == ENOSPC || errno == EDQUOT ?
		    MBOX_OP_ERR_OVERQUOTA : MBOX_OP_ERR_GENERIC;
		index_lock_release(&il);
		close(dfd);
		goto send;
	}

	/* Nothing above changed the selection. */
	if (ss->mailbox_dir_fd != -1)
		close(ss->mailbox_dir_fd);
	ss->mailbox_dir_fd = dfd;

	strlcpy(ss->selected_mailbox, target, sizeof(ss->selected_mailbox));

	reply.error = MBOX_OP_OK;
	ss->mailbox_selected = 1;
	reply.exists = (uint32_t)idx.nlines;
	reply.uidvalidity = idx.uidvalidity;
	reply.uidnext = idx.uidnext;
	reply.highestmodseq = idx.highestmodseq;

	if (req->qresync && req->qresync_uidvalidity == idx.uidvalidity)
		qresync_send_resync(req, ranges, nranges, &idx, ss);
	ss->nsaved = 0;
	idle_baseline_seed(ss, &idx);

	index_free(&idx);
	index_lock_release(&il);

send:
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_SELECTED, 0, 0, -1, &reply,
	    sizeof(reply)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_SELECTED",
		    ss->id);
	return (0);
}

int
ensure_maildir_dirs(int dfd, const char *prefix)
{
	static const char	*dirs[] = { "tmp", "new", "cur" };
	char			 path[PATH_MAX];
	size_t			 i;
	int			 ret;

	for (i = 0; i < nitems(dirs); i++) {
		ret = snprintf(path, sizeof(path), "%s%s", prefix, dirs[i]);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			log_warnx("mailbox path too long");
			return (-1);
		}
		if (mkdirat(dfd, path, 0700) == -1 && errno != EEXIST) {
			log_warn("mkdir %s", path);
			return (-1);
		}
	}
	return (0);
}

#define STORE_MINSPACE		5
#define STORE_MININODES		5

int
store_space_ok(int fd)
{
	struct statfs	sfs;
	uint64_t	used, avail;

	if (fstatfs(fd, &sfs) == -1) {
		log_warn("fstatfs");
		return (0);
	}
	used = sfs.f_blocks - sfs.f_bfree;
	avail = sfs.f_bavail > 0 ? (uint64_t)sfs.f_bavail : 0;
	if (sfs.f_blocks > 0 &&
	    avail * 100 < (avail + used) * STORE_MINSPACE) {
		log_warnx("under %d%% of the store's space free, refused",
		    STORE_MINSPACE);
		return (0);
	}
	used = sfs.f_files - sfs.f_ffree;
	avail = sfs.f_favail > 0 ? (uint64_t)sfs.f_favail : 0;
	if (sfs.f_files > 0 &&
	    avail * 100 < (avail + used) * STORE_MININODES) {
		log_warnx("under %d%% of the store's inodes free, refused",
		    STORE_MININODES);
		return (0);
	}
	return (1);
}

void
handle_mbox_create(struct imsg_mbox_name *req, struct store_session *ss)
{
	struct imsg_mbox_result	 result;
	char			 prefix[MBOX_NAME_MAX + 1];
	int			 ret;

	memset(&result, 0, sizeof(result));

	if (mailbox_name_is_inbox(req->mailbox) ||
	    !mailbox_name_valid(req->mailbox)) {
		log_debug("session %u: CREATE %s: invalid name", ss->id,
		    req->mailbox);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (!store_space_ok(maildir_root_fd)) {
		result.error = MBOX_OP_ERR_OVERQUOTA;
		goto send;
	}

	if (mkdirat(maildir_root_fd, req->mailbox, 0700) == -1) {
		if (errno != EEXIST) {
			result.error = errno == ENOSPC || errno == EDQUOT ?
			    MBOX_OP_ERR_OVERQUOTA : MBOX_OP_ERR_GENERIC;
			log_warn("session %u: CREATE: mkdir %s", ss->id,
			    req->mailbox);
		} else {
			log_debug("session %u: CREATE %s: already exists",
			    ss->id, req->mailbox);
			result.error = MBOX_OP_ERR_ALREADY_EXISTS;
		}
		goto send;
	}

	ret = snprintf(prefix, sizeof(prefix), "%s/", req->mailbox);
	if (ret < 0 || (size_t)ret >= sizeof(prefix) ||
	    ensure_maildir_dirs(maildir_root_fd, prefix) == -1) {
		unlinkat(maildir_root_fd, req->mailbox, AT_REMOVEDIR);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	result.error = MBOX_OP_OK;

send:
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

static int
remove_maildir_subtree(int dfd, const char *prefix)
{
	struct stat		 st;
	static const char	*dirs[] = { "tmp", "new", "cur" };
	/* List every file a mailbox holds, or rmdir(2) fails. */
	static const char	*files[] = {
		STORE_INDEX_NAME,
		STORE_INDEX_TMP_NAME,
		STORE_INDEX_LOCK_NAME,
	};
	char			 path[PATH_MAX];
	DIR			*dp;
	const struct dirent	*de;
	char			 entpath[PATH_MAX];
	size_t			 i;
	int			 ret, ok;

	for (i = 0; i < nitems(dirs); i++) {
		ok = 1;

		ret = snprintf(path, sizeof(path), "%s%s", prefix, dirs[i]);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			log_warnx("DELETE: path too long");
			return (-1);
		}
		if ((dp = opendirat(dfd, path)) == NULL) {
			if (errno == ENOENT)
				/* A missing directory has nothing to remove. */
				continue;
			log_warn("DELETE: opendir %s", path);
			return (-1);
		}
		while ((de = readdir(dp)) != NULL) {
			if (strcmp(de->d_name, ".") == 0 ||
			    strcmp(de->d_name, "..") == 0)
				continue;
			ret = snprintf(entpath, sizeof(entpath), "%s/%s", path,
			    de->d_name);
			if (ret < 0 || (size_t)ret >= sizeof(entpath)) {
				log_warnx("DELETE: entry path too long");
				ok = 0;
				continue;
			}
			if (fstatat(dfd, entpath, &st,
			    AT_SYMLINK_NOFOLLOW) == -1) {
				log_warn("DELETE: lstat %s", entpath);
				ok = 0;
				continue;
			}
			if (!S_ISREG(st.st_mode)) {
				log_warnx("DELETE %s: not a regular file",
				    entpath);
				ok = 0;
				continue;
			}
			if (unlinkat(dfd, entpath, 0) == -1) {
				log_warn("DELETE: unlink %s", entpath);
				ok = 0;
			}
		}
		closedir(dp);
		if (!ok)
			return (-1);
		if (unlinkat(dfd, path, AT_REMOVEDIR) == -1 &&
		    errno != ENOENT) {
			log_warn("DELETE: rmdir %s", path);
			return (-1);
		}
	}

	for (i = 0; i < nitems(files); i++) {
		ret = snprintf(path, sizeof(path), "%s%s", prefix, files[i]);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			log_warnx("DELETE: index path too long");
			return (-1);
		}
		if (unlinkat(dfd, path, 0) == -1 && errno != ENOENT) {
			log_warn("DELETE: unlink %s", path);
			return (-1);
		}
	}

	return (0);
}

void
handle_mbox_delete(struct imsg_mbox_name *req, struct store_session *ss)
{
	struct imsgev		*iev = &ss->iev;
	struct imsg_mbox_result	 result;
	struct stat		 st;
	char			 prefix[MBOX_NAME_MAX + 1];
	int			 ret;

	memset(&result, 0, sizeof(result));

	if (mailbox_name_is_inbox(req->mailbox) ||
	    !mailbox_name_valid(req->mailbox)) {
		log_debug("session %u: DELETE %s: invalid name", ss->id,
		    req->mailbox);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (fstatat(maildir_root_fd, req->mailbox, &st,
	    AT_SYMLINK_NOFOLLOW) == -1 || !S_ISDIR(st.st_mode)) {
		log_debug("session %u: DELETE %s: no such mailbox",
		    ss->id, req->mailbox);
		result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}

	ret = snprintf(prefix, sizeof(prefix), "%s/", req->mailbox);
	if (ret < 0 || (size_t)ret >= sizeof(prefix)) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (remove_maildir_subtree(maildir_root_fd, prefix) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}
	if (unlinkat(maildir_root_fd, req->mailbox, AT_REMOVEDIR) == -1 &&
	    errno != ENOENT) {
		log_warn("session %u: DELETE: rmdir %s", ss->id,
		    req->mailbox);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	result.error = MBOX_OP_OK;

send:
	if (result.error == MBOX_OP_OK)
		pcache_drop_mailbox(req->mailbox);
	/* Deleting the selected mailbox leaves none selected. */
	if (result.error == MBOX_OP_OK &&
	    strcmp(ss->selected_mailbox, req->mailbox) == 0)
		ss->mailbox_selected = 0;
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

/*
 * INBOX is the maildir root and cannot be renamed.
 */
void
handle_mbox_rename(struct imsg_mbox_rename *req, struct store_session *ss)
{
	struct imsgev		*iev = &ss->iev;
	struct imsg_mbox_result	 result;
	struct stat		 st;

	memset(&result, 0, sizeof(result));

	if (mailbox_name_is_inbox(req->oldname) ||
	    mailbox_name_is_inbox(req->newname) ||
	    !mailbox_name_valid(req->oldname) ||
	    !mailbox_name_valid(req->newname)) {
		log_debug("session %u: RENAME %s -> %s: invalid name(s)",
		    ss->id, req->oldname, req->newname);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (fstatat(maildir_root_fd, req->oldname, &st,
	    AT_SYMLINK_NOFOLLOW) == -1 || !S_ISDIR(st.st_mode)) {
		log_debug("session %u: RENAME %s: no such mailbox",
		    ss->id, req->oldname);
		result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}

	if (fstatat(maildir_root_fd, req->newname, &st,
	    AT_SYMLINK_NOFOLLOW) == 0) {
		log_debug("session %u: RENAME %s -> %s: destination exists",
		    ss->id, req->oldname, req->newname);
		result.error = MBOX_OP_ERR_ALREADY_EXISTS;
		goto send;
	}
	if (errno != ENOENT) {
		log_warn("session %u: RENAME: stat %s", ss->id,
		    req->newname);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (renameat(maildir_root_fd, req->oldname, maildir_root_fd,
	    req->newname) == -1) {
		log_warn("session %u: RENAME: rename %s -> %s", ss->id,
		    req->oldname, req->newname);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	result.error = MBOX_OP_OK;

send:
	if (result.error == MBOX_OP_OK)
		pcache_drop_mailbox(req->oldname);
	if (result.error == MBOX_OP_OK &&
	    strcmp(ss->selected_mailbox, req->oldname) == 0)
		strlcpy(ss->selected_mailbox, req->newname,
		    sizeof(ss->selected_mailbox));
	if (imsg_compose(&iev->ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

/*
 * LIST and subscriptions share this test for a mailbox.
 */
static int
mbox_root_entry_is_mailbox(const char *name, int *badname)
{
	struct stat	st;

	*badname = 0;

	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return (0);

	if (fstatat(maildir_root_fd, name, &st, AT_SYMLINK_NOFOLLOW) ==
	    -1 || !S_ISDIR(st.st_mode))
		return (0);

	/* The tmp, new and cur directories belong to INBOX. */
	if (strcmp(name, "tmp") == 0 || strcmp(name, "new") == 0 ||
	    strcmp(name, "cur") == 0 || mailbox_name_reserved(name))
		return (0);

	if (!mailbox_name_valid(name)) {
		*badname = 1;
		return (0);
	}
	return (1);
}

#define SUBLIST_INIT	{ NULL, 0, 0, 0 }

static void
sublist_free(struct sublist *sl)
{
	size_t	i;

	for (i = 0; i < sl->n; i++)
		free(sl->names[i]);
	free(sl->names);
	sl->names = NULL;
	sl->n = sl->cap = 0;
}

static int
sublist_has(const struct sublist *sl, const char *name)
{
	size_t	i;

	for (i = 0; i < sl->n; i++)
		if (strcmp(sl->names[i], name) == 0)
			return (1);
	return (0);
}

/*
 * Store a copy, so the caller keeps name.
 */
static int
sublist_add(struct sublist *sl, const char *name)
{
	size_t	newcap;
	char	*copy, **newnames;

	if (sl->n == sl->cap) {
		newcap = (sl->cap == 0) ? 16 : sl->cap * 2;

		if ((newnames = reallocarray(sl->names, newcap,
		    sizeof(*sl->names))) == NULL) {
			log_warn("reallocarray subscriptions");
			return (-1);
		}
		sl->names = newnames;
		sl->cap = newcap;
	}
	if ((copy = strdup(name)) == NULL) {
		log_warn("strdup subscription");
		return (-1);
	}
	sl->names[sl->n++] = copy;
	return (0);
}

static void
sublist_remove(struct sublist *sl, const char *name)
{
	size_t	i;

	for (i = 0; i < sl->n; i++) {
		if (strcmp(sl->names[i], name) != 0)
			continue;
		free(sl->names[i]);
		memmove(&sl->names[i], &sl->names[i + 1],
		    (sl->n - i - 1) * sizeof(*sl->names));
		sl->n--;
		return;
	}
}

static int
sublist_load(struct sublist *sl)
{
	size_t	 linesize = 0;
	FILE	*fp = NULL;
	char	*line = NULL;
	int	 fd;

	sl->present = 0;
	fd = openat(maildir_root_fd, STORE_SUBSCRIPTIONS_NAME, O_RDONLY);
	if (fd != -1 && (fp = fdopen(fd, "r")) == NULL)
		close(fd);
	if (fp == NULL) {
		if (errno == ENOENT)
			return (0);
		log_warn("open %s", STORE_SUBSCRIPTIONS_NAME);
		return (-1);
	}
	sl->present = 1;

	while (getline(&line, &linesize, fp) != -1) {
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0')
			continue;

		/* Only a hand edit puts such a name here. */
		if (!mailbox_name_syntax_ok(line)) {
			log_warnx("%s: unusable name, not parsed",
			    STORE_SUBSCRIPTIONS_NAME);
			goto fail;
		}
		if (sublist_has(sl, line))
			continue;
		if (sublist_add(sl, line) == -1)
			goto fail;
	}
	if (ferror(fp)) {
		log_warn("read %s", STORE_SUBSCRIPTIONS_NAME);
		goto fail;
	}
	free(line);
	fclose(fp);
	return (0);

fail:
	free(line);
	fclose(fp);
	sublist_free(sl);
	sl->present = 0;
	return (-1);
}

static int
sublist_save(const struct sublist *sl)
{
	size_t	 i;
	FILE	*fp;
	int	 fd;

	if (unlinkat(maildir_root_fd, STORE_SUBSCRIPTIONS_TMP_NAME, 0) ==
	    -1 && errno != ENOENT) {
		log_warn("unlink %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		return (-1);
	}
	if ((fd = openat(maildir_root_fd, STORE_SUBSCRIPTIONS_TMP_NAME,
	    O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		log_warn("open %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		return (-1);
	}
	if ((fp = fdopen(fd, "w")) == NULL) {
		log_warn("fdopen %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		close(fd);
		return (-1);
	}

	for (i = 0; i < sl->n; i++) {
		if (fprintf(fp, "%s\n", sl->names[i]) < 0) {
			log_warnx("write %s failed",
			    STORE_SUBSCRIPTIONS_TMP_NAME);
			fclose(fp);
			return (-1);
		}
	}
	if (fflush(fp) != 0) {
		log_warn("fflush %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		fclose(fp);
		return (-1);
	}
	if (fsync(fileno(fp)) == -1) {
		log_warn("fsync %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		fclose(fp);
		return (-1);
	}
	if (fclose(fp) != 0) {
		log_warn("fclose %s", STORE_SUBSCRIPTIONS_TMP_NAME);
		return (-1);
	}

	if (renameat(maildir_root_fd, STORE_SUBSCRIPTIONS_TMP_NAME,
	    maildir_root_fd, STORE_SUBSCRIPTIONS_NAME) == -1) {
		log_warn("rename %s -> %s", STORE_SUBSCRIPTIONS_TMP_NAME,
		    STORE_SUBSCRIPTIONS_NAME);
		return (-1);
	}

	/* Sync the directory, so the rename survives a crash. */
	if (fsync(maildir_root_fd) == -1)
		log_warn("fsync maildir root (continuing)");
	return (0);
}

static int
subs_lock_acquire(int *lockfd)
{
	if ((*lockfd = openat(maildir_root_fd,
	    STORE_SUBSCRIPTIONS_LOCK_NAME,
	    O_RDWR | O_CREAT, 0600)) == -1) {
		log_warn("open %s", STORE_SUBSCRIPTIONS_LOCK_NAME);
		return (-1);
	}
	if (flock(*lockfd, LOCK_EX) == -1) {
		log_warn("flock %s", STORE_SUBSCRIPTIONS_LOCK_NAME);
		close(*lockfd);
		*lockfd = -1;
		return (-1);
	}
	return (0);
}

static void
subs_lock_release(int lockfd)
{
	if (lockfd == -1)
		return;
	flock(lockfd, LOCK_UN);
	close(lockfd);
}

/*
 * Build the list that an absent file stands for.
 */
static int
subs_materialise(struct sublist *sl)
{
	struct dirent	*de;
	DIR		*dp;
	int		 badname;

	if ((dp = opendirat(maildir_root_fd, ".")) == NULL) {
		log_warn("UNSUBSCRIBE: opendir .");
		return (-1);
	}
	while ((de = readdir(dp)) != NULL) {
		if (!mbox_root_entry_is_mailbox(de->d_name, &badname))
			continue;
		if (sublist_add(sl, de->d_name) == -1) {
			closedir(dp);
			return (-1);
		}
	}
	closedir(dp);
	sl->present = 1;
	return (0);
}

static int
list_item_send(struct store_session *ss, const char *name, int exists)
{
	struct imsg_mbox_list_item	item;

	memset(&item, 0, sizeof(item));
	strlcpy(item.mailbox, name, sizeof(item.mailbox));
	item.exists = exists;
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_LIST_ITEM, 0, 0, -1, &item,
	    sizeof(item)) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_LIST_ITEM",
		    ss->id);
		return (0);
	}
	return (1);
}

/*
 * INBOX is left out, as the listener answers it.
 */
void
handle_mbox_list(struct imsg_mbox_list *req, struct store_session *ss)
{
	struct imsg_mbox_result	 result;
	struct sublist		 sl = SUBLIST_INIT;
	struct dirent		*de;
	struct stat		 st;
	static int		 skip_warned;
	size_t			 i;
	DIR			*dp;
	int			 badname;

	memset(&result, 0, sizeof(result));

	if (req->subscribed_only && sublist_load(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if ((dp = opendirat(maildir_root_fd, ".")) == NULL) {
		log_warn("session %u: LIST: opendir .", ss->id);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	while ((de = readdir(dp)) != NULL) {
		if (!mbox_root_entry_is_mailbox(de->d_name, &badname)) {
			/* A skipped name may hide real mail. */
			if (badname && !skip_warned) {
				skip_warned = 1;
				log_warnx("session %u: LIST: %s: invalid "
				    "mailbox name, skipped",
				    ss->id, de->d_name);
			}
			continue;
		}
		if (req->subscribed_only && sl.present &&
		    !sublist_has(&sl, de->d_name))
			continue;
		if (list_item_send(ss, de->d_name, 1))
			result.count++;
	}
	closedir(dp);

	/* Subscribed names whose mailbox is gone are listed too. */
	for (i = 0; i < sl.n; i++) {
		if (fstatat(maildir_root_fd, sl.names[i], &st,
		    AT_SYMLINK_NOFOLLOW) != -1 && S_ISDIR(st.st_mode))
			continue;
		if (list_item_send(ss, sl.names[i], 0))
			result.count++;
	}
	result.error = MBOX_OP_OK;

send:
	sublist_free(&sl);
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

void
handle_mbox_subscribe(struct imsg_mbox_name *req, struct store_session *ss)
{
	struct imsg_mbox_result	 result;
	struct sublist		 sl = SUBLIST_INIT;
	struct stat		 st;
	int			 lockfd = -1;

	memset(&result, 0, sizeof(result));

	if (mailbox_name_is_inbox(req->mailbox)) {
		result.error = MBOX_OP_OK;
		goto send;
	}
	if (!mailbox_name_valid(req->mailbox)) {
		log_debug("session %u: SUBSCRIBE %s: invalid name", ss->id,
		    req->mailbox);
		result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}

	/* A server may refuse a nonexistent mailbox. */
	if (fstatat(maildir_root_fd, req->mailbox, &st,
	    AT_SYMLINK_NOFOLLOW) == -1 || !S_ISDIR(st.st_mode)) {
		log_debug("session %u: SUBSCRIBE %s: no such mailbox",
		    ss->id, req->mailbox);
		result.error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		goto send;
	}

	if (subs_lock_acquire(&lockfd) == -1 || sublist_load(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	/* With no file, every mailbox is already subscribed. */
	if (!sl.present || sublist_has(&sl, req->mailbox)) {
		result.error = MBOX_OP_OK;
		goto send;
	}
	if (sublist_add(&sl, req->mailbox) == -1 || sublist_save(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}
	result.error = MBOX_OP_OK;

send:
	sublist_free(&sl);
	subs_lock_release(lockfd);
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

void
handle_mbox_unsubscribe(struct imsg_mbox_name *req, struct store_session *ss)
{
	struct imsg_mbox_result	 result;
	struct sublist		 sl = SUBLIST_INIT;
	int			 lockfd = -1;

	memset(&result, 0, sizeof(result));

	if (mailbox_name_is_inbox(req->mailbox)) {
		log_debug("session %u: UNSUBSCRIBE INBOX: refused",
		    ss->id);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}
	/* A subscription may outlive its mailbox. */
	if (!mailbox_name_valid(req->mailbox)) {
		log_debug("session %u: UNSUBSCRIBE %s: invalid name",
		    ss->id, req->mailbox);
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	if (subs_lock_acquire(&lockfd) == -1 || sublist_load(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}

	/* The first UNSUBSCRIBE writes out what no file meant. */
	if (!sl.present && subs_materialise(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}
	if (!sublist_has(&sl, req->mailbox)) {
		result.error = MBOX_OP_OK;
		goto send;
	}

	sublist_remove(&sl, req->mailbox);
	if (sublist_save(&sl) == -1) {
		result.error = MBOX_OP_ERR_GENERIC;
		goto send;
	}
	result.error = MBOX_OP_OK;

send:
	sublist_free(&sl);
	subs_lock_release(lockfd);
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_RESULT, 0, 0, -1, &result,
	    sizeof(result)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_RESULT",
		    ss->id);
}

const char *
append_hostname(void)
{
	static char	hostbuf[HOST_NAME_MAX + 1];
	static int	resolved;

	if (!resolved) {
		if (gethostname(hostbuf, sizeof(hostbuf)) == -1) {
			log_warn("gethostname");
			strlcpy(hostbuf, "aimap", sizeof(hostbuf));
		}
		resolved = 1;
	}
	return (hostbuf);
}

void
append_abort(struct store_session *ss)
{
	struct store_append	*ap = &ss->append;

	if (!ap->active)
		return;
	if (ap->tmpfd != -1)
		close(ap->tmpfd);
	if (ap->tmppath[0] != '\0' && ap->tfd != -1)
		unlinkat(ap->tfd, ap->tmppath, 0);
	if (ap->tfd != -1)
		close(ap->tfd);
	memset(ap, 0, sizeof(*ap));
}

static void
append_reply(struct store_session *ss, const struct imsg_mbox_appended *reply)
{
	if (imsg_compose(&ss->iev.ibuf, IMSG_MBOX_APPENDED, 0, 0, -1, reply,
	    sizeof(*reply)) == -1)
		log_warn("session %u: imsg_compose IMSG_MBOX_APPENDED",
		    ss->id);
}

void
handle_mbox_append_begin(struct store_session *ss,
    const struct imsg_mbox_append *req)
{
	struct store_append	*ap = &ss->append;
	int64_t			 delivery_ts;
	char			 target[MBOX_NAME_MAX];
	int			 ret;

	if (ap->active) {
		log_warnx("session %u: APPEND begun with another in flight, "
		    "abandoning the first", ss->id);
		append_abort(ss);
	}
	memset(ap, 0, sizeof(*ap));
	ap->active = 1;
	ap->tfd = -1;
	ap->tmpfd = -1;
	ap->req = *req;
	ap->remaining = req->msglen;

	/* Failed until the tmp/ file is open. */
	ap->failed = 1;
	ap->error = MBOX_OP_ERR_GENERIC;

	if (req->msglen > append_max) {
		log_warnx("session %u: APPEND of %llu octets is over the %llu "
		    "octet limit", ss->id, (unsigned long long)req->msglen,
		    (unsigned long long)append_max);
		return;
	}
	if (!index_field_valid(req->keywords)) {
		log_warnx("session %u: APPEND: unsafe keywords field",
		    ss->id);
		return;
	}

	if (mailbox_name_is_inbox(req->mailbox))
		target[0] = '\0';
	else if (!mailbox_name_valid(req->mailbox) ||
	    strlcpy(target, req->mailbox, sizeof(target)) >= sizeof(target)) {
		log_debug("session %u: APPEND: invalid mailbox name",
		    ss->id);
		ap->error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		return;
	}

	if ((ap->tfd = mailbox_open_dir(target)) == -1) {
		log_debug("session %u: APPEND %s: no such mailbox",
		    ss->id, req->mailbox);
		ap->error = MBOX_OP_ERR_NO_SUCH_MAILBOX;
		return;
	}
	if (!store_space_ok(ap->tfd)) {
		ap->error = MBOX_OP_ERR_OVERQUOTA;
		return;
	}
	if (ensure_maildir_dirs(ap->tfd, "") == -1)
		return;

	delivery_ts = req->has_date ? req->date : (int64_t)time(NULL);
	ret = snprintf(ap->basename, sizeof(ap->basename), "%lld.%d_%u.%s",
	    (long long)delivery_ts, (int)getpid(), append_counter++,
	    append_hostname());
	if (ret < 0 || (size_t)ret >= sizeof(ap->basename)) {
		log_warnx("session %u: generated basename too long",
		    ss->id);
		return;
	}
	ret = snprintf(ap->tmppath, sizeof(ap->tmppath), "tmp/%s",
	    ap->basename);
	if (ret < 0 || (size_t)ret >= sizeof(ap->tmppath)) {
		log_warnx("session %u: tmp path too long", ss->id);
		ap->tmppath[0] = '\0';
		return;
	}
	if ((ap->tmpfd = openat(ap->tfd, ap->tmppath,
	    O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		if (errno == ENOSPC || errno == EDQUOT)
			ap->error = MBOX_OP_ERR_OVERQUOTA;
		log_warn("session %u: open %s", ss->id, ap->tmppath);
		/* The file O_EXCL found may not be ours. */
		ap->tmppath[0] = '\0';
		return;
	}
	ap->failed = 0;
}

void
handle_mbox_append_data(struct store_session *ss, const char *buf, size_t len)
{
	struct store_append	*ap = &ss->append;
	ssize_t			 n;
	size_t			 written = 0;

	if (!ap->active) {
		log_warnx("session %u: APPEND data with no APPEND in flight, "
		    "ignoring", ss->id);
		return;
	}
	if (len > ap->remaining) {
		log_warnx("session %u: APPEND data past the announced length",
		    ss->id);
		ap->failed = 1;
		ap->error = MBOX_OP_ERR_GENERIC;
		ap->remaining = 0;
		return;
	}
	ap->remaining -= len;
	if (ap->failed)
		return;

	while (written < len) {
		n = write(ap->tmpfd, buf + written, len - written);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			ap->error = errno == ENOSPC || errno == EDQUOT ?
			    MBOX_OP_ERR_OVERQUOTA : MBOX_OP_ERR_GENERIC;
			log_warn("session %u: write %s", ss->id,
			    ap->tmppath);
			ap->failed = 1;
			return;
		}
		written += (size_t)n;
	}
}

/*
 * Rename into cur/ before the index changes.  A crash between leaves a file
 * that the next refresh adopts.
 */
int
handle_mbox_append_end(struct store_session *ss)
{
	struct store_append		*ap = &ss->append;
	struct imsg_mbox_appended	 reply;
	struct mbox_index		 idx;
	struct index_lock		 il = INDEX_LOCK_INIT;
	char				 curpath[PATH_MAX];
	char				 letters[8];
	char				 line[STORE_INDEX_LINE_MAX];
	int				 locked, ret, r, n;

	memset(&idx, 0, sizeof(idx));
	memset(&reply, 0, sizeof(reply));
	reply.error = MBOX_OP_ERR_GENERIC;

	if (!ap->active) {
		log_warnx("session %u: APPEND end with no APPEND in flight",
		    ss->id);
		append_reply(ss, &reply);
		return (0);
	}
	if (!ap->failed && ap->remaining != 0) {
		log_warnx("session %u: APPEND ended %llu octets short",
		    ss->id, (unsigned long long)ap->remaining);
		ap->failed = 1;
		ap->error = MBOX_OP_ERR_GENERIC;
	}
	if (ap->failed) {
		reply.error = ap->error;
		goto done;
	}

	/* A retry after a busy lock finds this done. */
	if (ap->tmpfd != -1) {
		if ((r = fsync(ap->tmpfd)) == 0) {
			r = close(ap->tmpfd);
			ap->tmpfd = -1;
		}
		if (r == -1) {
			reply.error = errno == ENOSPC || errno == EDQUOT ?
			    MBOX_OP_ERR_OVERQUOTA : MBOX_OP_ERR_GENERIC;
			log_warn("session %u: fsync or close %s", ss->id,
			    ap->tmppath);
			goto done;
		}
	}

	locked = index_lock_acquire(ap->tfd, &il, LOCK_EX | LOCK_NB);
	if (locked == INDEX_LOCK_BUSY)
		return (1);
	if (locked == INDEX_LOCK_ERR)
		goto done_index;
	if (index_load(il.fd, &idx) == -1)
		goto done_index;

	sysflags_to_letters(ap->req.sysflags, letters, sizeof(letters));
	ret = snprintf(curpath, sizeof(curpath), "cur/%s:2,%s", ap->basename,
	    letters);
	if (ret < 0 || (size_t)ret >= sizeof(curpath)) {
		log_warnx("session %u: cur path too long for %s", ss->id,
		    ap->basename);
		goto done_index;
	}
	if (renameat(ap->tfd, ap->tmppath, ap->tfd, curpath) == -1) {
		log_warn("session %u: rename %s -> %s", ss->id, ap->tmppath,
		    curpath);
		goto done_index;
	}
	ap->tmppath[0] = '\0';	/* Now in cur/, so keep it. */

	reply.uid = idx.uidnext;
	if (index_append(&idx, reply.uid, ap->basename) == -1)
		goto unlink_cur;
	idx.uidnext++;

	if (ap->req.keywords[0] != '\0') {
		n = snprintf(line, sizeof(line), "%u:%s:%s:%llu", reply.uid,
		    ap->basename, ap->req.keywords,
		    (unsigned long long)idx.highestmodseq);
		if (n < 0 || (size_t)n >= sizeof(line)) {
			log_warnx("session %u: index line too long for %s",
			    ss->id, ap->basename);
			goto unlink_cur;
		}
		free(idx.lines[idx.nlines - 1]);
		if ((idx.lines[idx.nlines - 1] = strdup(line)) == NULL) {
			log_warn("session %u: strdup index line", ss->id);
			goto unlink_cur;
		}
	}

	if (index_save(ap->tfd, &idx) == -1)
		goto unlink_cur;

	reply.uidvalidity = idx.uidvalidity;
	if (ss->mailbox_selected && strcmp(ss->selected_mailbox,
	    mailbox_name_is_inbox(ap->req.mailbox) ? "" : ap->req.mailbox) == 0)
		(void)view_sync(ss, &idx, 1);
	index_lock_release(&il);
	index_free(&idx);
	reply.error = MBOX_OP_OK;
	goto done;

unlink_cur:
	if (unlinkat(ap->tfd, curpath, 0) == -1)
		log_warn("session %u: unlink %s, left on disk", ss->id,
		    curpath);
done_index:
	index_lock_release(&il);
	index_free(&idx);
done:
	append_abort(ss);
	append_reply(ss, &reply);
	return (0);
}
