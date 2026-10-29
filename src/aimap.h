#ifndef AIMAP_H
#define AIMAP_H

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>

#define AIMAP_VERSION	"0.0.1"

#define AIMAP_USER	"_aimap"
#define AIMAP_AUTH_USER	"_aimapauth"
#define PATH_CHROOT	"/var/empty"

enum aimap_proc_type {
	PROC_PARENT,
	PROC_LISTENER,
	PROC_AUTH,
	PROC_STORE,
	PROC_KEYMGR,
	PROC_PARSER
};

enum imsg_type {
	IMSG_NONE,

	/* The setup handshake between the parent and its children. */
	IMSG_SETUP_PEER,
	IMSG_SETUP_DONE,

	IMSG_TLS_CERT,

	/* An accepted connection, passed to the listener. */
	IMSG_LISTENER_SESSION_INIT,

	IMSG_AUTH_INIT,

	IMSG_AUTH_REQUEST,
	IMSG_AUTH_RESULT,

	/* The TLS private key, at boot and on SIGHUP. */
	IMSG_KEYMGR_INIT,

	/* A reply reuses its request's type and id. */
	IMSG_KEYMGR_RSA_PRIVENC,
	IMSG_KEYMGR_RSA_PRIVDEC,
	IMSG_KEYMGR_ECDSA_SIGN,

	IMSG_KEYMGR_SHUTDOWN,

	IMSG_AUTH_CRED,
	IMSG_AUTH_EXIT,

	IMSG_STORE_FORK,
	IMSG_STORE_INIT,
	IMSG_STORE_SHUTDOWN,
	IMSG_STORE_EXIT,

	/* Only a uid, since the parser opens nothing. */
	IMSG_PARSER_INIT,
	/* Ask for a parser, which arrives as IMSG_SETUP_PEER. */
	IMSG_PARSER_WANT,
	IMSG_PARSER_NONE,

	/* A reply reuses its request's type and id. */
	IMSG_PARSER_ENVELOPE,
	IMSG_PARSER_BODYSTRUCTURE,
	IMSG_PARSER_HEADER_FIELDS,
	IMSG_PARSER_PART,
	IMSG_PARSER_SEARCH,

	/* SELECT carries EXAMINE, with readonly set. */
	IMSG_MBOX_SELECT,
	IMSG_MBOX_SELECTED,
	IMSG_MBOX_FETCH,
	IMSG_MBOX_FETCH_META,
	IMSG_MBOX_FETCH_HEADER,
	IMSG_MBOX_FETCH_BODY,
	IMSG_MBOX_FETCH_ENVELOPE,
	IMSG_MBOX_FETCH_BODYSTRUCTURE,
	IMSG_MBOX_STORE,
	IMSG_MBOX_APPEND,
	IMSG_MBOX_APPEND_DATA,
	IMSG_MBOX_APPEND_END,
	IMSG_MBOX_APPENDED,
	IMSG_MBOX_COPY,
	IMSG_MBOX_MOVE,
	IMSG_MBOX_COPY_MAPPING,
	IMSG_MBOX_EXPUNGE,
	IMSG_MBOX_EXPUNGED,
	IMSG_MBOX_SEARCH,
	IMSG_MBOX_SEARCH_MATCH,
	IMSG_MBOX_LIST,
	IMSG_MBOX_STATUS,
	IMSG_MBOX_STATUS_RESULT,
	IMSG_MBOX_CREATE,
	IMSG_MBOX_DELETE,
	IMSG_MBOX_RENAME,
	IMSG_MBOX_RESULT,

	IMSG_MBOX_SELECT_VANISHED,
	IMSG_MBOX_STORE_MODIFIED,

	/* The VIEW messages may follow any command. */
	IMSG_MBOX_IDLE_REFRESH,
	IMSG_MBOX_VIEW_EXPUNGE,
	IMSG_MBOX_VIEW_FETCH,
	IMSG_MBOX_VIEW_EXISTS,
	IMSG_MBOX_IDLE_REFRESHED,

	IMSG_MBOX_LIST_ITEM,

	IMSG_MBOX_SUBSCRIBE,
	IMSG_MBOX_UNSUBSCRIBE,
	IMSG_MBOX_SAVED_CLEAR
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	void		*data;
	short		 events;
};

#define LISTENER_MAX_ADDRS	2

struct aimap_config {
	char	 listen_addr[64];
	uint16_t port_cleartext;	/* STARTTLS port, or 0 if unset */
	uint16_t port_implicit_tls;	/* TLS port, or 0 if unset */
	char	 spool_root[PATH_MAX];
	char	 cred_file[PATH_MAX];
	char	 userbase_file[PATH_MAX];
	char	 tls_cert_file[PATH_MAX];
	char	 tls_key_file[PATH_MAX];
	uint32_t bodystructure_read_max;
	uint64_t append_max;

	uint32_t max_startups_begin;
	uint32_t max_startups_rate;	/* Percent, 0 to 100 */
	uint32_t max_startups_full;
	uint32_t max_startups_per_source;

	uint32_t idle_poll_secs;
	uint32_t lock_timeout_secs;
	uint32_t login_grace_secs;
	uint32_t account_sessions;
	uint32_t connections_max;
};

#define AUTH_USERNAME_MAX	64
#define AUTH_PASSWORD_MAX	128

/* A file sent in pieces and reassembled. */
struct imsg_tls_chunk {
	size_t		len;
	size_t		offset;
};

struct imsg_listener_session_init {
	uint32_t		session_id;
	int			implicit_tls;
	struct sockaddr_storage	remote_ss;
	socklen_t		remote_sslen;
	uint32_t		idle_poll_secs;
	uint32_t		login_grace_secs;
	uint64_t		append_max;
};

struct imsg_auth_init {
	char		cred_file[PATH_MAX];
};

#define KEYMGR_HASH_MAX	80	/* SHA256: hash with room to spare */
#define KEYMGR_DATA_MAX	1024

/* A request is this header, then fromlen bytes. */
struct imsg_keymgr_sign_request {
	char		hash[KEYMGR_HASH_MAX];
	/* Ignored for ECDSA. */
	uint32_t	padding;
	uint32_t	fromlen;
};

struct imsg_keymgr_sign_reply {
	/* A failure fails one TLS operation, not the listener. */
	int		ok;
	uint32_t	tolen;
};

struct imsg_auth_request {
	uint32_t	session_id;
	char		username[AUTH_USERNAME_MAX];
	char		password[AUTH_PASSWORD_MAX];
};

struct imsg_auth_result {
	uint32_t	session_id;
	int		ok;
};

struct imsg_auth_cred {
	uint32_t	session_id;
	char		username[AUTH_USERNAME_MAX];
};

#define STORE_MAILDIR_MAX	256

struct imsg_store_fork {
	uint32_t	session_id;
	int		limit;	/* Refused by account sessions */
};

struct imsg_parser_init {
	uid_t		uid;
	gid_t		gid;
	uint32_t	bodystructure_read_max;
};

struct imsg_store_init {
	uid_t		uid;
	gid_t		gid;
	char		spool_root[PATH_MAX];
	/* Relative to spool_root. */
	char		maildir[STORE_MAILDIR_MAX];
	uint32_t	bodystructure_read_max;
	uint64_t	append_max;
	uint32_t	lock_timeout_secs;
};

#define MBOX_NAME_MAX	256

enum mbox_op_error {
	MBOX_OP_UNSET = 0,
	MBOX_OP_OK,
	MBOX_OP_ERR_GENERIC,
	MBOX_OP_ERR_NO_SUCH_MAILBOX,
	MBOX_OP_ERR_ALREADY_EXISTS,
	MBOX_OP_ERR_BUSY,
	MBOX_OP_ERR_EXPUNGEISSUED,
	MBOX_OP_ERR_LIMIT,
	MBOX_OP_ERR_NOTSAVED,
	MBOX_OP_ERR_OVERQUOTA,
};

struct imsg_mbox_select {
	char		mailbox[MBOX_NAME_MAX];
	int		readonly;	/* EXAMINE if 1, SELECT if 0 */

	int		qresync;
	uint32_t	qresync_uidvalidity;
	uint64_t	qresync_modseq;
	int		qresync_has_uids;
	uint32_t	qresync_nranges;
};

/* Any VANISHED, then FETCH_META, messages come first. */
struct imsg_mbox_selected {
	enum mbox_op_error error;
	uint32_t	exists;
	uint32_t	uidvalidity;
	uint32_t	uidnext;
	uint64_t	highestmodseq;

};

#define STATUS_ATT_MESSAGES		(1U << 0)
#define STATUS_ATT_UIDNEXT		(1U << 1)
#define STATUS_ATT_UIDVALIDITY		(1U << 2)
#define STATUS_ATT_UNSEEN		(1U << 3)
#define STATUS_ATT_DELETED		(1U << 4)
#define STATUS_ATT_SIZE			(1U << 5)
#define STATUS_ATT_HIGHESTMODSEQ	(1U << 6)
#define STATUS_ATT_RECENT		(1U << 7)	/* Always answered 0 */

/* STATUS leaves the selection alone. */
struct imsg_mbox_status {
	char		mailbox[MBOX_NAME_MAX];
	uint32_t	attrs;
};

struct imsg_mbox_status_result {
	enum mbox_op_error error;
	uint32_t	messages;
	uint32_t	uidnext;
	uint32_t	uidvalidity;
	uint64_t	highestmodseq;
	uint32_t	unseen;
	uint32_t	deleted;
	uint64_t	size;
};

/* One gap, uid_lo to uid_hi inclusive. */
struct imsg_mbox_select_vanished {
	uint32_t	uid_lo;
	uint32_t	uid_hi;
};

#define MBOX_FLAGS_MAX	256	/* Truncated if exceeded */

#define MBOX_FETCH_FLAGS		(1U << 0)
#define MBOX_FETCH_UID			(1U << 1)
#define MBOX_FETCH_INTERNALDATE	(1U << 2)
#define MBOX_FETCH_RFC822_SIZE		(1U << 3)
#define MBOX_FETCH_MODSEQ		(1U << 4)
#define MBOX_FETCH_BODY_HEADER		(1U << 5)
#define MBOX_FETCH_BODY_WHOLE		(1U << 6)
#define MBOX_FETCH_BODY_TEXT		(1U << 7)
#define MBOX_FETCH_HEADER_FIELDS	(1U << 8)
#define MBOX_FETCH_ENVELOPE		(1U << 9)
#define MBOX_FETCH_BODYSTRUCTURE	(1U << 10) /* Also bare BODY */
#define MBOX_FETCH_BODY_PART		(1U << 11)
#define MBOX_FETCH_SET_SEEN		(1U << 12)

#define SECTION_PART_MAX	40

#define FETCH_HEADER_MAX	8192

/* The base system MTA's default message size limit. */
#define APPEND_MAX_DEFAULT	((uint64_t)35 * 1024 * 1024)
#define APPEND_MAX_MAX		1073741824

#define FETCH_BATCH_MAX		((size_t)1024 * 1024)

/* Each descriptor holds a kern.maxfiles slot until sent. */
#define FETCH_FD_MAX		16

#define HEADER_FIELDS_MAX	256

#define ENVELOPE_MAX	8192

/* The longest wait for a parser or keymgr reply. */
#define PARSER_REPLY_TIMEOUT_SEC	10
#define KEYMGR_REPLY_TIMEOUT_SEC	10

/* SIGXCPU at the soft limit, SIGKILL at the hard. */
#define PARSER_CPU_SOFT_SEC	8
#define PARSER_CPU_HARD_SEC	10

/* Retire at half the soft limit, before SIGXCPU. */
#define PARSER_CPU_RETIRE_SEC	(PARSER_CPU_SOFT_SEC / 2)

#define PARSER_IDLE_SEC		60

#define PARSER_STRIKES		3

/* A message's headers claim these, so both are bounded. */
#define MIME_MAX_DEPTH	10
#define MIME_MAX_PARTS	64

#define BODYSTRUCTURE_MAX	12000

#define IDLE_POLL_DEFAULT	5
#define IDLE_POLL_MAX		300	/* Seconds, and 0 disables polling */

/* A short timer before authentication is allowed. */
#define LOGIN_GRACE_DEFAULT	60
#define LOGIN_GRACE_MAX		3600	/* Seconds, and 0 disables the timer */

/* Wait this long for a lock, then answer INUSE. */
#define LOCK_TIMEOUT_DEFAULT	120
#define LOCK_TIMEOUT_MAX	3600	/* Seconds, and 0 disables the bound */

/* The account sessions maximum equals OPEN_SESSION_MAX. */
#define ACCOUNT_SESSIONS_DEFAULT	8
#define ACCOUNT_SESSIONS_MAX		4096

/* The connections max maximum equals OPEN_SESSION_MAX. */
#define CONNECTIONS_MAX_DEFAULT		256
#define CONNECTIONS_MAX_MAX		4096

#define STARTUPS_PER_SOURCE_DEFAULT	5
#define STARTUPS_MAX			1000000

/* For attachment max, as delivered mail ignores append max. */
#define BODYSTRUCTURE_READ_DEFAULT	41943040
#define BODYSTRUCTURE_READ_MAX		1073741824

/* Each request passes a read-only message descriptor. */
struct imsg_parser_req {
	char		basename[NAME_MAX + 1];
	char		fields[HEADER_FIELDS_MAX];
	int		fields_not;
	int		path[MIME_MAX_DEPTH];
	int		pathlen;
	uint32_t	nleaves;
	uint32_t	poollen;
};

/* A content key, its strings offsets into the pool. */
struct imsg_parser_leaf {
	int32_t		op;
	uint32_t	str_off;
	uint32_t	str_len;
	uint32_t	name_off;
	uint32_t	name_len;
	int64_t		num;		/* For SENT*, the day's UTC midnight */
};

struct imsg_parser_rep {
	int		found;
	uint32_t	len;
	uint64_t	part_off;
	uint64_t	part_len;
	uint32_t	retiring;
};

/* A sequence-set range, "*" resolved by the store. */
struct seq_range {
	uint32_t	lo;
	uint32_t	hi;
	int		lo_is_star;
	int		hi_is_star;
};

/* The saved result "$" is the all-zero range. */
#define SEQ_RANGE_SAVED(r)	((r)->lo == 0 && !(r)->lo_is_star)

/* Keeps the trailing array under MAX_IMSGSIZE. */
#define SEQSET_MAX_RANGES	500

struct imsg_mbox_fetch {
	uint32_t	nranges;
	uint32_t	attrs;

	int		has_changedsince;
	uint64_t	changedsince;

	int		by_uid;
	int		want_vanished;

	int		header_fields_not;
	char		header_fields[HEADER_FIELDS_MAX];

	/* One section-part per FETCH, the last one given. */
	char		section_part[SECTION_PART_MAX];
	int		has_partial;
	uint32_t	partial_start;
	uint32_t	partial_count;
};

struct imsg_mbox_fetch_meta {
	uint32_t	seqno;
	uint32_t	uid;
	uint64_t	size;
	int64_t		internaldate;	/* From the basename, not mtime */
	char		flags[MBOX_FLAGS_MAX];
	uint64_t	modseq;
	int		seen_set;
};

/* Sent just before that message's IMSG_MBOX_FETCH_META. */
struct imsg_mbox_fetch_header {
	uint32_t	seqno;
	uint32_t	uid;
	int		found;
	uint32_t	hdrlen;
};

/* The octets travel as a passed descriptor. */
struct imsg_mbox_fetch_body {
	uint32_t	seqno;
	uint32_t	uid;
	int		found;
	uint64_t	offset;
	uint64_t	length;		/* Octets, with no descriptor if 0 */
};

/* The store checks this holds no CR or LF. */
struct imsg_mbox_fetch_envelope {
	uint32_t	seqno;
	uint32_t	uid;
	int		found;
	uint32_t	envlen;
};

struct imsg_mbox_fetch_bodystructure {
	uint32_t	seqno;
	uint32_t	uid;
	int		found;
	uint32_t	bslen;
};

struct imsg_mbox_result {
	enum mbox_op_error error;
	uint32_t	count;
	uint64_t	highestmodseq;	/* The selected mailbox's */

	/* For COPYUID, after COPY and MOVE only. */
	uint32_t	uidvalidity;
};

/*
 * Keywords may hold no colon or comma.  The index cannot escape them.
 */
#define MBOX_FLAG_ANSWERED	(1U << 0)
#define MBOX_FLAG_FLAGGED	(1U << 1)
#define MBOX_FLAG_DELETED	(1U << 2)
#define MBOX_FLAG_SEEN		(1U << 3)
#define MBOX_FLAG_DRAFT		(1U << 4)

#define MBOX_STORE_SET		0
#define MBOX_STORE_ADD		1
#define MBOX_STORE_REMOVE	2

struct imsg_mbox_store {
	uint32_t	nranges;
	int		mode;
	int		silent;
	uint32_t	sysflags;
	char		keywords[MBOX_FLAGS_MAX];

	int		has_unchangedsince;
	uint64_t	unchangedsince;

	int		by_uid;
};

struct imsg_mbox_store_modified {
	uint32_t	seqno;
	uint32_t	uid;
};

/* Expunges are reported lowest first, each renumbering the rest. */
struct imsg_mbox_expunge {
	int		silent;	/* CLOSE if 1, EXPUNGE if 0 */

	/* Ranges come only with UID EXPUNGE. */
	int		by_uid;
	uint32_t	nranges;
};

struct imsg_mbox_expunged {
	uint32_t	seqno;	/* As renumbered by earlier EXPUNGEs */
	uint32_t	uid;	/* For VANISHED */
};

struct imsg_mbox_copy {
	int		by_uid;
	uint32_t	nranges;
	char		destname[MBOX_NAME_MAX];
};

/* COPYUID pairs, sent before any EXPUNGE for MOVE. */
struct imsg_mbox_copy_mapping {
	uint32_t	src_uid;
	uint32_t	dest_uid;
};

/* The literal follows as APPEND_DATA pieces, then APPEND_END. */
struct imsg_mbox_append {
	char		mailbox[MBOX_NAME_MAX];
	uint32_t	sysflags;
	char		keywords[MBOX_FLAGS_MAX];
	int		has_date;
	int64_t		date;
	uint64_t	msglen;
};

struct imsg_mbox_appended {
	enum mbox_op_error error;	/* NO_SUCH_MAILBOX means TRYCREATE */
	uint32_t	uidvalidity;
	uint32_t	uid;		/* For APPENDUID, with uidvalidity */
};

/* A search program is a postfix array of nodes. */
#define SEARCH_PROGRAM_MAX_NODES	100
#define SEARCH_KEYWORD_MAX		64	/* One keyword, not a list */
/* The operand pool, sized as a non-synchronizing literal. */
#define SEARCH_OPERANDS_MAX		4096

#define SEARCH_OP_ALL		0
#define SEARCH_OP_ANSWERED	1
#define SEARCH_OP_UNANSWERED	2
#define SEARCH_OP_DELETED	3
#define SEARCH_OP_UNDELETED	4
#define SEARCH_OP_DRAFT		5
#define SEARCH_OP_UNDRAFT	6
#define SEARCH_OP_FLAGGED	7
#define SEARCH_OP_UNFLAGGED	8
#define SEARCH_OP_SEEN		9
#define SEARCH_OP_UNSEEN	10
#define SEARCH_OP_KEYWORD	11
#define SEARCH_OP_UNKEYWORD	12
#define SEARCH_OP_BEFORE	13
#define SEARCH_OP_ON		14
#define SEARCH_OP_SINCE		15
#define SEARCH_OP_LARGER	16
#define SEARCH_OP_SMALLER	17
#define SEARCH_OP_SEQSET	18
#define SEARCH_OP_UIDSET	19
#define SEARCH_OP_AND		20
#define SEARCH_OP_OR		21
#define SEARCH_OP_NOT		22
#define SEARCH_OP_MODSEQ	23
/* The keys below are answered by the parser. */
#define SEARCH_OP_SUBJECT	24
#define SEARCH_OP_HEADER	25
#define SEARCH_OP_SENTBEFORE	26
#define SEARCH_OP_SENTON	27
#define SEARCH_OP_SENTSINCE	28
#define SEARCH_OP_FROM		29
#define SEARCH_OP_TO		30
#define SEARCH_OP_CC		31
#define SEARCH_OP_BCC		32
#define SEARCH_OP_BODY		33
#define SEARCH_OP_TEXT		34
#define SEARCH_OP_SAVED		35

struct search_node {
	int		op;
	int64_t		num;
	uint32_t	seq_lo;
	uint32_t	seq_hi;
	int		lo_is_star;
	int		hi_is_star;
	char		keyword[SEARCH_KEYWORD_MAX];
	uint32_t	str_off;	/* Into the pool */
	uint32_t	str_len;
	uint32_t	name_off;
	uint32_t	name_len;
};

#define SEARCH_RETURN_MIN	(1U << 0)
#define SEARCH_RETURN_MAX	(1U << 1)
#define SEARCH_RETURN_ALL	(1U << 2)
#define SEARCH_RETURN_COUNT	(1U << 3)
#define SEARCH_RETURN_SAVE	(1U << 4)

struct imsg_mbox_search {
	uint32_t	nnodes;
	uint32_t	poollen;
	uint32_t	return_opts;
	char		pool[SEARCH_OPERANDS_MAX];
};

#define SEARCH_ARGS_MAX			8192

/* The errmsg is a static string. */
struct search_parse_result {
	int		rc;
	uint32_t	nnodes;
	int		uses_modseq;
	const char	*errmsg;
	uint32_t	poollen;
	char		pool[SEARCH_OPERANDS_MAX];
};

struct imsg_mbox_search_match {
	uint32_t	seqno;
	uint32_t	uid;
	uint64_t	modseq;
};

/* For IDLE and NOOP, with expunges sent separately. */
struct imsg_mbox_idle_refreshed {
	int		ok;
	int		unchanged;	/* The probe saw no change */
	int		busy;	/* Lock busy, ok if still seeded */
};

struct imsg_mbox_view_exists {
	uint32_t	exists;
};

/* The store checks the name again. */
struct imsg_mbox_name {
	char		mailbox[MBOX_NAME_MAX];
};

struct imsg_mbox_rename {
	char		oldname[MBOX_NAME_MAX];
	char		newname[MBOX_NAME_MAX];
};

/* Unordered, and INBOX is not included. */
struct imsg_mbox_list {
	int		subscribed_only;
};

/* An exists of 0 means subscribed, with no mailbox. */
struct imsg_mbox_list_item {
	char		mailbox[MBOX_NAME_MAX];
	int		exists;
};

const char	*proc_name(enum aimap_proc_type);

int		 parse_config(const char *, struct aimap_config *);
int		 cmdline_symset(char *);
int		 check_file_secrecy(int, const char *);
int		 table_line(char *, char **, char **);

__dead void	 parent_main(const char *, int, char *[],
		    struct aimap_config *, int);

/* Each role's configuration arrives over fd 3. */
__dead void	 listener_main(void);
__dead void	 auth_main(void);
__dead void	 store_main(void);
__dead void	 keymgr_main(void);
__dead void	 parser_main(void);

void		 imsgev_ibuf_init(struct imsgbuf *, int);
void		 imsgev_init(struct imsgev *, int,
		    void (*)(int, short, void *), void *);
void		 imsgev_init_from_ibuf(struct imsgev *, const struct imsgbuf *,
		    void (*)(int, short, void *), void *);

/* A dispatch handler must call this before returning. */
void		 imsgev_rearm_read(struct imsgev *);
int		 recv_fixed(struct imsg *, void *, size_t, const char *);
int		 recv_header(struct imsg *, struct ibuf *, void *, size_t,
		    const char *);
int		 recv_chunk(struct imsg *, char **, size_t *, size_t *,
		    const char *);

int		 setup_recv_one_peer(struct imsgbuf *);
void		 setup_recv_done_and_ack(struct imsgbuf *);

#endif
