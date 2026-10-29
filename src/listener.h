/*
 * Command parsers return 0, -1 for BAD, or PARSE_NO, and on failure set
 * *errmsg.  The rest return 0 or -1, or 1 or 0.
 */

#ifndef LISTENER_H
#define LISTENER_H

#include <sys/types.h>

#include <event.h>
#include <stdint.h>
#include <time.h>
#include <tls.h>

#define PARSE_NO	(-2)

enum session_state {
	SESSION_NOT_AUTH,
	SESSION_AUTHENTICATING,
	SESSION_STORE_PENDING,
	SESSION_AUTHENTICATED,
	SESSION_SELECTING,
	SESSION_SELECTED,
	SESSION_FETCHING,
	SESSION_STORING,
	SESSION_EXPUNGING,
	SESSION_APPENDING,
	SESSION_SEARCHING,
	SESSION_STATUSING,
	SESSION_COPYING,

	/* Each returns to mbox_op_prev_state when done. */
	SESSION_CREATING,
	SESSION_DELETING,
	SESSION_RENAMING,
	SESSION_LISTING,
	SESSION_SUBSCRIBING,
	SESSION_UNSUBSCRIBING
};

/* Bounds a client that never sends CRLF. */
#define SESSION_INBUF_MAX	8192

#define IMAP_TAG_MAX	64

/* Past this many pipelined lines, the session is dropped. */
#define SESSION_CMD_QUEUE_MAX	8

#define HEADER_FIELDS_LABEL_MAX	288

/* Two DQUOTEs, a NUL and a backslash per byte. */
#define MBOX_QUOTED_MAX		((2 * MBOX_NAME_MAX) + 3)

/* A mod-sequence is a positive 63-bit integer. */
#define MODSEQ_MAX		INT64_MAX

struct vanished_range {
	uint32_t	lo;
	uint32_t	hi;
};

/* The command in flight, cleared when the next starts. */
struct session_cmd {
	/* A copy, since the next read overwrites inbuf. */
	char			 pending_tag[IMAP_TAG_MAX];
	uint32_t		 fetch_attrs;

	char			*pending_header_buf;
	uint32_t		 pending_header_len;
	int			 pending_header_found;
	char			 pending_header_label[HEADER_FIELDS_LABEL_MAX];
	int			 pending_body_fd;	/* Or -1 if none */
	uint64_t		 pending_body_off;
	uint64_t		 pending_body_len;
	int			 pending_body_found;
	char			 pending_body_label[SECTION_PART_MAX];
	/* Only the origin is echoed back. */
	int			 pending_body_has_partial;
	uint32_t		 pending_body_partial_origin;
	char			*pending_envelope_buf;
	uint32_t		 pending_envelope_len;
	int			 pending_envelope_found;
	char			*pending_bodystructure_buf;
	uint32_t		 pending_bodystructure_len;
	int			 pending_bodystructure_found;
	char			 pending_bodystructure_label[16];

	/* The tagged reply is NO, not OK. */
	int			 fetch_incomplete;

	int			 close_after_expunge;

	char			 append_mailbox[MBOX_NAME_MAX];
	enum session_state	 append_prev_state;

	uint32_t		 status_attrs;
	char			 status_mailbox[MBOX_NAME_MAX];
	enum session_state	 status_prev_state;

	enum session_state	 mbox_op_prev_state;
	char			 list_pattern[2 * MBOX_NAME_MAX];
	int			 list_is_lsub;
	int			 list_subscribed_only;
	/* RENAME moves the selection, and DELETE clears it. */
	char			 mbox_op_name[MBOX_NAME_MAX];
	char			 rename_newname[MBOX_NAME_MAX];

	uint32_t		 search_return_opts;
	uint32_t		*search_matches;
	uint32_t		 search_nmatches;
	uint32_t		 search_matches_cap;
	/* A failed realloc(3) fails the SEARCH. */
	int			 search_alloc_failed;
	int			 search_used_modseq;
	uint64_t		 search_max_modseq;

	/* The reply IDLE or NOOP owes after the refresh. */
	const char		*refresh_status;
	const char		*refresh_text;

	/* Held until IMSG_MBOX_SELECTED, to keep the order. */
	struct vanished_range	*vanished_ranges;
	uint32_t		 vanished_nranges;
	uint32_t		 vanished_cap;
	struct imsg_mbox_fetch_meta *qresync_fetches;
	uint32_t		 qresync_nfetches;
	uint32_t		 qresync_fetches_cap;
	/* A dropped entry fails SELECT, or HIGHESTMODSEQ hides it. */
	int			 qresync_alloc_failed;

	/* Kept so COPYUID can precede the EXPUNGEs. */
	uint32_t		*copy_src_uids;
	uint32_t		*copy_dest_uids;
	uint32_t		 copy_n;
	uint32_t		 copy_cap;
	int			 copy_alloc_failed;
	int			 cmd_is_move;
	struct imsg_mbox_expunged *move_expunged;
	uint32_t		 move_expunged_n;
	uint32_t		 move_expunged_cap;

	uint32_t		*store_modified;
	uint32_t		 store_modified_n;
	uint32_t		 store_modified_cap;
	/* MODIFIED lists every failure, so a partial set fails. */
	int			 store_modified_alloc_failed;

	int			 cmd_by_uid;
};

struct session {
	uint32_t		 id;
	int			 client_fd;
	/* Numeric, so no dns pledge is needed. */
	char			 remote_addr[64];
	char			 user[AUTH_USERNAME_MAX];
	struct timespec		 connected_at;
	struct event		 client_ev;
	enum session_state	 state;
	int			 implicit_tls;
	struct imsgev		*store_iev;
	/* Only then is event_del() on client_ev safe. */
	int			 client_ev_added;
	int			 write_failed;
	int			 tls_active;
	struct tls		*tls_ctx;
	/* The greeting waits for the TLS handshake. */
	int			 pending_greeting;
	char			 inbuf[SESSION_INBUF_MAX];
	size_t			 inbuflen;
	/* Credentials passed through inbuf, so explicit_bzero(3) it. */
	int			 scrub_inbuf;
	int			 auth_cont;
	/* In IDLE, the next line is DONE. */
	int			 idling;
	/* Pipelined lines, each from malloc(3). */
	char			*cmd_queue[SESSION_CMD_QUEUE_MAX];
	uint32_t		 cmd_queue_n;

	/* Literal octets are read before the CRLF search. */
	int			 literal_pending;
	uint64_t		 literal_len;	/* Size announced in {n} */
	uint64_t		 literal_remaining;
	/* Discard a refused literal's octets, then its line. */
	uint64_t		 literal_discard;
	int			 literal_skipline;
	/* A command gathered with its literals. */
	char			 cmdbuf[SESSION_INBUF_MAX];
	size_t			 cmdlen;
	size_t			 cmd_octets;
	int			 cmd_gather;
	int			 cmd_queued;	/* Bound for the queue */
	int			 wants_literal;

	/* Never cleared, and QRESYNC implies CONDSTORE. */
	int			 condstore_enabled;
	int			 qresync_enabled;
	uint64_t		 mbox_highestmodseq;
	int			 mbox_readonly;
	char			 selected_mailbox[MBOX_NAME_MAX];

	/* For IDLE, the store keeps the UID list. */
	int			 idle_refresh_pending;
	int			 idle_refresh_again;
	struct event		 idle_ev;
	struct event		 grace_ev;

	struct session_cmd	 cmd;
};

extern struct imsgev		 iev_auth;
extern struct imsgev		 iev_parent;
extern struct tls		*listener_tls_ctx;

#define IMAP_BUSY_TEXT	"[INUSE] mailbox busy, try again"
#define IMAP_OVERQUOTA_TEXT	"[OVERQUOTA] not enough free space"

extern uint32_t			 listener_idle_poll_secs;
extern uint32_t			 listener_login_grace_secs;
extern uint64_t			 listener_append_max;
extern const char		 literal_wanted[];

void	 session_store_dispatch(int, short, void *);
void	 session_send_fetch_response(struct session *,
		    struct imsg_mbox_fetch_meta *);
void	 session_send_store_fetch_response(struct session *,
		    const struct imsg_mbox_fetch_meta *);
void	 session_send_expunge_response(struct session *,
		    const struct imsg_mbox_expunged *);
void	 session_finish_append(struct session *);
void	 session_handle_mbox_appended(struct session *,
		    const struct imsg_mbox_appended *);

extern const char	*fetch_month_names[12];
void	 line_append(char *, size_t, size_t *, const char *, ...)
		    __attribute__((__format__ (printf, 4, 5)));
int	 parse_nz_number(const char *, uint32_t *);
int	 parse_sequence_set(const char *,
		    struct seq_range[SEQSET_MAX_RANGES], uint32_t *,
		    const char **);
int	 parse_store_flags(char *, uint32_t *, char *, size_t,
		    const char **);
void	 session_handle_mbox_search_match(struct session *,
		    struct imsg_mbox_search_match *);
void	 session_finish_search(struct session *,
		    struct imsg_mbox_result *);
__dead void	 session_teardown(struct session *, const char *);

void	 session_condstore_enable(struct session *);
size_t	 format_seq_list(char *, size_t, const uint32_t *, uint32_t,
		    int *);
size_t	 format_range_list(char *, size_t,
		    const struct vanished_range *, uint32_t, int *);
void	 session_handle_store_modified(struct session *,
		    struct imsg_mbox_store_modified *);
int	 session_request_idle_refresh(struct session *);
void	 session_idle_poll_init(struct session *);
void	 session_idle_poll_arm(struct session *);
void	 session_idle_poll_disarm(struct session *);
void	 session_handle_idle_continuation(struct session *, const char *);

void	 fetch_dispatch(struct session *, const char *, char *, int);
void	 search_dispatch(struct session *, const char *, char *, int);
void	 session_handle_fetch_vanished(struct session *,
		    const struct imsg_mbox_select_vanished *);

int	 listener_mailbox_name_valid(const char *);
int	 listener_check_utf8(struct session *, const char *, const char *);
int	 list_pattern_match(const char *, const char *, int);
int	 parse_mailbox_name(char **, char *, size_t, const char **);
int	 read_literal(char **, char **, size_t *, const char **);
int	 read_sp(char **, const char **);
int	 next_word(char **, char **, const char **);
int	 read_quoted(const char *, char *, size_t, size_t *, size_t *,
		    const char **);
char	*match_paren(char *);
const char	*mbox_error_text(enum mbox_op_error, const char *, char *,
		    size_t);
void	 session_arg_error(struct session *, const char *, const char *);
int	 quote_mailbox(char *, size_t, const char *);
void	 session_finish_copy_or_move(struct session *,
		    const struct imsg_mbox_result *);

void	 session_tls_start(struct session *);

void	 session_write(struct session *, const char *, size_t);
void	 session_reply(struct session *, const char *, const char *,
		    const char *);
void	 session_untagged(struct session *, const char *);
int	 send_mbox_request(struct session *, int, const char *, const void *,
		    size_t, const void *, uint32_t, size_t);
void	 session_dequeue_next(struct session *);
void	 session_handle_auth_continuation(struct session *, const char *);

void	 cmd_capability(struct session *, const char *, char *);
void	 cmd_noop(struct session *, const char *, char *);
void	 cmd_logout(struct session *, const char *, char *);
void	 cmd_id(struct session *, const char *, char *);
void	 cmd_login(struct session *, const char *, char *);
void	 cmd_starttls(struct session *, const char *, char *);
void	 cmd_authenticate(struct session *, const char *, char *);

void	 cmd_enable(struct session *, const char *, char *);
void	 cmd_select(struct session *, const char *, char *);
void	 cmd_examine(struct session *, const char *, char *);
void	 cmd_create(struct session *, const char *, char *);
void	 cmd_delete(struct session *, const char *, char *);
void	 cmd_rename(struct session *, const char *, char *);
void	 cmd_subscribe(struct session *, const char *, char *);
void	 cmd_unsubscribe(struct session *, const char *, char *);
void	 cmd_list(struct session *, const char *, char *);
void	 cmd_lsub(struct session *, const char *, char *);
void	 cmd_namespace(struct session *, const char *, char *);
void	 cmd_status(struct session *, const char *, char *);
void	 cmd_append(struct session *, const char *, char *);
void	 cmd_idle(struct session *, const char *, char *);

void	 cmd_close(struct session *, const char *, char *);
void	 cmd_unselect(struct session *, const char *, char *);
void	 cmd_expunge(struct session *, const char *, char *);
void	 cmd_search(struct session *, const char *, char *);
void	 cmd_fetch(struct session *, const char *, char *);
void	 cmd_store_cmd(struct session *, const char *, char *);
void	 cmd_copy(struct session *, const char *, char *);
void	 cmd_move(struct session *, const char *, char *);
void	 cmd_uid(struct session *, const char *, char *);

#endif
