#ifndef AIMAP_MBOXNAME_H
#define AIMAP_MBOXNAME_H

/*
 * Names of the store's own files, refused as mailbox names.  Locks are
 * taken on the .lock files, because the index is replaced by rename(2) and
 * flock(2) locks an inode.  The uidvalidity file is rewritten in place and
 * is its own lock.  An index lock may be held while taking the uidvalidity
 * lock, but not the other way round.  The subscriptions lock is taken
 * alone, and a missing subscriptions file means every mailbox is
 * subscribed.
 */
#define STORE_INDEX_NAME		"aimap.index"
#define STORE_INDEX_TMP_NAME		"aimap.index.tmp"
#define STORE_INDEX_LOCK_NAME		"aimap.index.lock"
#define STORE_UIDVALIDITY_NAME		"aimap.uidvalidity"
#define STORE_SUBSCRIPTIONS_NAME	"aimap.subscriptions"
#define STORE_SUBSCRIPTIONS_TMP_NAME	"aimap.subscriptions.tmp"
#define STORE_SUBSCRIPTIONS_LOCK_NAME	"aimap.subscriptions.lock"

/* The listener and the store share this name check. */
int	 mailbox_name_syntax_ok(const char *);

int	 mailbox_name_reserved(const char *);

int	 mailbox_name_is_inbox(const char *);

#endif
