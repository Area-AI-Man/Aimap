/*
 * ENVELOPE and BODYSTRUCTURE text from the parser, after parser_request()
 * has checked it, kept in the account's store process.  The key is the
 * mailbox name, UIDVALIDITY and UID, and the message's file name is checked
 * on every hit.  The oldest entries are evicted first.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "store_internal.h"

struct pcache_entry {
	RB_ENTRY(pcache_entry)		 node;
	TAILQ_ENTRY(pcache_entry)	 lru;
	const char			*mailbox;	/* After the struct */
	uint32_t			 uid;
	uint32_t			 uidvalidity;
	const char			*basename;	/* After the mailbox */
	char				*text[PCACHE_NITEMS];
	uint32_t			 len[PCACHE_NITEMS];
	size_t				 bytes;
};

RB_HEAD(pcache_tree, pcache_entry);
TAILQ_HEAD(pcache_lru, pcache_entry);

static int			 pcache_cmp(struct pcache_entry *,
				    struct pcache_entry *);
static struct pcache_entry	*pcache_find(const char *, uint32_t, uint32_t,
				    const char *);
static void			 pcache_free(struct pcache_entry *);

RB_PROTOTYPE_STATIC(pcache_tree, pcache_entry, node, pcache_cmp);
RB_GENERATE_STATIC(pcache_tree, pcache_entry, node, pcache_cmp);

static struct pcache_tree pcache_root = RB_INITIALIZER(&pcache_root);
static struct pcache_lru pcache_age = TAILQ_HEAD_INITIALIZER(pcache_age);
static size_t		 pcache_bytes, pcache_entries;

static struct {
	unsigned long long	 hit, miss, add, evict, drop, stale;
	size_t			 peak_bytes, peak_entries;
} pcache_stat;

/*
 * Order by name then UID, grouping each mailbox's entries.
 */
static int
pcache_cmp(struct pcache_entry *a, struct pcache_entry *b)
{
	int	 c;

	if ((c = strcmp(a->mailbox, b->mailbox)) != 0)
		return (c);
	if (a->uid != b->uid)
		return (a->uid < b->uid ? -1 : 1);
	return (0);
}

static void
pcache_free(struct pcache_entry *e)
{
	int	 i;

	RB_REMOVE(pcache_tree, &pcache_root, e);
	TAILQ_REMOVE(&pcache_age, e, lru);
	pcache_bytes -= e->bytes;
	pcache_entries--;
	for (i = 0; i < PCACHE_NITEMS; i++)
		free(e->text[i]);
	free(e);
}

/*
 * Another UIDVALIDITY or file name means another message.
 */
static struct pcache_entry *
pcache_find(const char *mailbox, uint32_t uidvalidity, uint32_t uid,
    const char *basename)
{
	struct pcache_entry	 key, *e;

	key.mailbox = mailbox;
	key.uid = uid;
	if ((e = RB_FIND(pcache_tree, &pcache_root, &key)) == NULL)
		return (NULL);
	if (e->uidvalidity != uidvalidity ||
	    strcmp(e->basename, basename) != 0) {
		pcache_stat.stale++;
		pcache_free(e);
		return (NULL);
	}
	return (e);
}

/*
 * The text returned is valid until the next pcache_put().
 */
const char *
pcache_get(const char *mailbox, uint32_t uidvalidity, uint32_t uid,
    const char *basename, int item, uint32_t *lenp)
{
	struct pcache_entry	*e;

	e = pcache_find(mailbox, uidvalidity, uid, basename);
	if (e == NULL || e->text[item] == NULL) {
		pcache_stat.miss++;
		return (NULL);
	}
	pcache_stat.hit++;
	TAILQ_REMOVE(&pcache_age, e, lru);
	TAILQ_INSERT_HEAD(&pcache_age, e, lru);
	*lenp = e->len[item];
	return (e->text[item]);
}

void
pcache_put(const char *mailbox, uint32_t uidvalidity, uint32_t uid,
    const char *basename, int item, const char *text, uint32_t len)
{
	struct pcache_entry	*e, *old;
	size_t			 mblen, bnlen;
	char			*p;

	if (len == 0 || len > PCACHE_BYTES_MAX / 2)
		return;
	if ((e = pcache_find(mailbox, uidvalidity, uid, basename)) == NULL) {
		mblen = strlen(mailbox) + 1;
		bnlen = strlen(basename) + 1;
		if ((e = calloc(1, sizeof(*e) + mblen + bnlen)) == NULL) {
			log_warn("parse cache entry");
			return;
		}
		p = (char *)(e + 1);
		memcpy(p, mailbox, mblen);
		e->mailbox = p;
		memcpy(p + mblen, basename, bnlen);
		e->basename = p + mblen;
		e->uid = uid;
		e->uidvalidity = uidvalidity;
		e->bytes = sizeof(*e) + mblen + bnlen;
		RB_INSERT(pcache_tree, &pcache_root, e);
		pcache_bytes += e->bytes;
		pcache_entries++;
	} else
		TAILQ_REMOVE(&pcache_age, e, lru);
	TAILQ_INSERT_HEAD(&pcache_age, e, lru);

	if (e->text[item] != NULL) {
		pcache_bytes -= e->len[item];
		e->bytes -= e->len[item];
		free(e->text[item]);
		e->text[item] = NULL;
	}
	while (pcache_bytes + len > PCACHE_BYTES_MAX &&
	    (old = TAILQ_LAST(&pcache_age, pcache_lru)) != e) {
		pcache_stat.evict++;
		pcache_free(old);
	}
	if ((e->text[item] = malloc(len)) == NULL) {
		log_warn("parse cache text");
		return;
	}
	memcpy(e->text[item], text, len);
	e->len[item] = len;
	e->bytes += len;
	pcache_bytes += len;
	pcache_stat.add++;
	if (pcache_bytes > pcache_stat.peak_bytes)
		pcache_stat.peak_bytes = pcache_bytes;
	if (pcache_entries > pcache_stat.peak_entries)
		pcache_stat.peak_entries = pcache_entries;
}

void
pcache_drop_uid(const char *mailbox, uint32_t uid)
{
	struct pcache_entry	 key, *e;

	key.mailbox = mailbox;
	key.uid = uid;
	if ((e = RB_FIND(pcache_tree, &pcache_root, &key)) != NULL) {
		pcache_stat.drop++;
		pcache_free(e);
	}
}

void
pcache_drop_mailbox(const char *mailbox)
{
	struct pcache_entry	 key, *e, *next;

	key.mailbox = mailbox;
	key.uid = 0;
	for (e = RB_NFIND(pcache_tree, &pcache_root, &key);
	    e != NULL && strcmp(e->mailbox, mailbox) == 0; e = next) {
		next = RB_NEXT(pcache_tree, &pcache_root, e);
		pcache_stat.drop++;
		pcache_free(e);
	}
}

/*
 * A new UIDVALIDITY drops the mailbox's old entries.
 */
void
pcache_check_mailbox(const char *mailbox, uint32_t uidvalidity)
{
	struct pcache_entry	 key, *e;

	key.mailbox = mailbox;
	key.uid = 0;
	e = RB_NFIND(pcache_tree, &pcache_root, &key);
	if (e != NULL && strcmp(e->mailbox, mailbox) == 0 &&
	    e->uidvalidity != uidvalidity)
		pcache_drop_mailbox(mailbox);
}

void
pcache_log(void)
{
	if (pcache_stat.hit == 0 && pcache_stat.miss == 0)
		return;
	log_info("uid %u: parse cache: %llu hits, %llu misses, "
	    "%llu added, %llu evicted, %llu dropped, %llu stale, "
	    "peak %zu entries, %zu bytes", (unsigned int)getuid(),
	    pcache_stat.hit, pcache_stat.miss, pcache_stat.add,
	    pcache_stat.evict, pcache_stat.drop, pcache_stat.stale,
	    pcache_stat.peak_entries, pcache_stat.peak_bytes);
}
