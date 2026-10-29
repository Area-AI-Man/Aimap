/*
 * The handle_mbox_*() functions return 0 once answered and 1 to defer on a
 * busy index lock.  The rest return 0 or -1, or 1 or 0, unless a definition
 * says otherwise.
 */

#ifndef STORE_INTERNAL_H
#define STORE_INTERNAL_H

#include <sys/types.h>
#include <sys/queue.h>

#include <dirent.h>
#include <limits.h>
#include <stdint.h>

#include "mboxname.h"

struct mbox_index {
	uint32_t	  uidvalidity;
	uint32_t	  uidnext;
	uint64_t	  highestmodseq;
	/* With no index found, save this UIDVALIDITY before unlocking. */
	int		  fresh;
	/* Lines in the form UID:basename:keywords:MODSEQ. */
	char		**lines;
	size_t		  nlines;
	size_t		  cap;
};

/* Three-field lines, from before CONDSTORE, have modseq 1. */
struct index_rec {
	uint32_t	uid;
	char		basename[NAME_MAX + 1];
	char		keywords[512];
	uint64_t	modseq;
};

struct copy_staged {
	uint32_t	src_uid;
	uint32_t	dest_uid;
	char		basename[NAME_MAX + 1];
	char		keywords[512];
	uint32_t	sysflags;
	char		*srcpath;
	off_t		srcsize;
};

/* FETCH walks pause for draining output or a reply. */
struct store_fetch_walk {
	int				 active;
	struct mbox_index		 idx;
	struct imsg_mbox_fetch		 req;
	struct seq_range		 resolved[SEQSET_MAX_RANGES];
	struct index_rec		 rec;		/* Record being sent */
	struct imsg_mbox_fetch_meta	 meta;
	uint32_t			 nresolved;
	uint32_t			 max_hi;
	uint32_t			 next;
	uint32_t			 sent;
	size_t				 composed;
	int				 fds;
	int				 in_msg;	/* Part of rec sent */
	int				 stage;		/* Next item of rec */
	int				 have_file;
	int				 part_fd;	/* For BODY[<part>] */
	int				 wait_parser;	/* Parser awaited */
	int				 wait_reply;	/* Request is out */
	int				 no_parser;	/* Go on without */
	int				 ghost;
	int				 limit;
	uint64_t			 seen_modseq;
};

struct search_msg_ctx {
	uint32_t	seqno;
	uint32_t	uid;
	uint32_t	sysflags;
	const char	*keywords;
	int64_t		internaldate;
	uint64_t	size;
	uint64_t	modseq;
	const struct seq_range	*saved;
	uint32_t	nsaved;
};

/* A SEARCH walk yields to the account's other sessions. */
struct store_search_walk {
	int			 active;
	int			 wait_parser;	/* Parser awaited */
	int			 wait_reply;	/* Request for msg is out */
	struct search_msg_ctx	 msg;
	struct index_rec	 rec;
	struct event		 yield_ev;
	struct mbox_index	 idx;
	struct search_node	 nodes[SEARCH_PROGRAM_MAX_NODES];
	uint32_t		 nnodes;
	uint32_t		 leafidx[SEARCH_PROGRAM_MAX_NODES];
	uint32_t		 nleaves;
	uint32_t		 poollen;
	char			 extra[SEARCH_PROGRAM_MAX_NODES *
				    sizeof(struct imsg_parser_leaf) +
				    SEARCH_OPERANDS_MAX];
	size_t			 extralen;
	uint32_t		 next;		/* Index line to resume at */
	uint32_t		 sent;
	uint32_t		 walked;
	uint32_t		 opts;
	struct seq_range	 sv[SEQSET_MAX_RANGES];
	uint32_t		 nsv;
	uint32_t		 sv_line;
	uint32_t		 sv_first;
	uint32_t		 sv_last;
	int			 sv_full;
};

/* Stat the mailbox and new/ without the lock. */
struct store_idle_probe {
	int		 valid;
	ino_t		 dir_ino;
	ino_t		 new_ino;
	struct timespec	 dir_mtim;
	struct timespec	 new_mtim;
};

/* UIDs last reported, so a change costs one imsg. */
struct store_idle_baseline {
	uint32_t	*uids;
	size_t		 n;
	uint64_t	 modseq;	/* Highest reported, above is news */
	size_t		 ghosts;	/* Expunged, not yet reported */
	int		 valid;
};

/* A failure is held until the APPEND ends. */
struct store_append {
	int			  active;
	int			  failed;
	enum mbox_op_error	  error;
	struct imsg_mbox_append	  req;
	uint64_t		  remaining;
	int			  tfd;
	int			  tmpfd;
	char			  basename[NAME_MAX + 1];
	char			  tmppath[PATH_MAX];
};

/* Read cur/ once per command, then discard the listing. */
struct cur_snapshot {
	int	  dfd;		/* Directory listed, or -1 */
	int	  failed;
	char	**names;
	size_t	  n;
};

union mbox_request {
	struct imsg_mbox_select		 select;
	struct imsg_mbox_fetch		 fetch;
	struct imsg_mbox_store		 store;
	struct imsg_mbox_expunge	 expunge;
	struct imsg_mbox_search		 search;
	struct imsg_mbox_status		 status;
	struct imsg_mbox_copy		 copy;
	struct imsg_mbox_append		 append;
	struct imsg_mbox_list		 list;
	struct imsg_mbox_name		 name;
	struct imsg_mbox_rename		 rename;
};

/* Commands the index lock defers rerun from the top. */
struct store_deferred {
	int			 active;
	uint32_t		 type;
	struct event		 ev;
	struct timespec		 give_up_at;
	unsigned int		 wait_ms;
	union mbox_request	 req;
	union {
		struct seq_range	 ranges[SEQSET_MAX_RANGES];
		struct search_node	 nodes[SEARCH_PROGRAM_MAX_NODES];
	} elts;
	uint32_t		 nelts;
};

/* Name and route may be NULL. */
struct address {
	char	*name;
	size_t	 namelen;
	char	*route;
	size_t	 routelen;
	char	*mailbox;
	size_t	 mailboxlen;
	char	*host;
	size_t	 hostlen;
};

/* RFC 2046 section 5.1.1. */
#define MIME_BOUNDARY_MAX	70

struct content_type {
	char	type[64];
	char	subtype[64];
	char	boundary[MIME_BOUNDARY_MAX + 1];
	int	has_boundary;
};

#define ADDR_MAILBOX	1
#define ADDR_GROUP	2
#define ADDR_GROUP_END	3

/* A PART asker keeps fd open until the reply. */
struct parser_ask {
	uint32_t		 type;
	const char		*label;
	int			 fd;
	const char		*basename;
	struct imsg_parser_req	*req;
	void			*extra;
	size_t			 extralen;
	uint32_t		 maxlen;
};

struct store_session {
	uint32_t			 id;
	TAILQ_ENTRY(store_session)	 entry;
	struct imsgev			 iev;

	/* A failed SELECT leaves nothing selected. */
	int				 mailbox_selected;

	/* Empty for INBOX. */
	char				 selected_mailbox[MBOX_NAME_MAX];

	int				 mailbox_dir_fd;

	struct cur_snapshot		 cur_snap;
	struct store_deferred		 deferred;
	struct store_fetch_walk		 fetch;
	struct store_search_walk	 search;
	struct store_idle_probe		 idle_probe;
	struct store_idle_baseline	 idle_baseline;
	struct store_append		 append;

	/* The search result variable, as UID ranges. */
	struct seq_range		 saved[SEQSET_MAX_RANGES];
	uint32_t			 nsaved;
};

extern uint32_t	 append_counter; /* Unique across APPEND and COPY */
extern int	 maildir_root_fd;

extern uint32_t	 bodystructure_read_max;
extern uint64_t	 append_max;
extern uint32_t	 lock_timeout_secs;

int	 handle_mbox_select(struct imsg_mbox_select *,
		    const struct seq_range *, uint32_t, struct store_session *);
int	 handle_mbox_fetch(struct imsg_mbox_fetch *,
		    const struct seq_range *, uint32_t, struct store_session *);
int	 handle_mbox_store(struct imsg_mbox_store *,
		    const struct seq_range *, uint32_t, struct store_session *);
struct store_step;
int	 store_apply(struct store_session *,
		    const struct imsg_mbox_store *, struct mbox_index *,
		    const struct seq_range *, uint32_t, int, int,
		    const uint64_t *, struct store_step **, size_t *);
int	 handle_mbox_expunge(struct imsg_mbox_expunge *,
		    const struct seq_range *, uint32_t, struct store_session *);
void	 handle_mbox_append_begin(struct store_session *,
		    const struct imsg_mbox_append *);
void	 handle_mbox_append_data(struct store_session *, const char *,
		    size_t);
int	 handle_mbox_append_end(struct store_session *);
void	 append_abort(struct store_session *);
int	 handle_mbox_search(struct imsg_mbox_search *,
		    struct search_node *, uint32_t, struct store_session *);
int	 handle_mbox_status(struct imsg_mbox_status *, struct store_session *);
int	 handle_mbox_copy(struct imsg_mbox_copy *,
		    const struct seq_range *, uint32_t, struct store_session *);
int	 handle_mbox_move(struct imsg_mbox_copy *,
		    const struct seq_range *, uint32_t, struct store_session *);
void	 handle_mbox_create(struct imsg_mbox_name *, struct store_session *);
void	 handle_mbox_delete(struct imsg_mbox_name *, struct store_session *);
void	 handle_mbox_rename(struct imsg_mbox_rename *, struct store_session *);
void	 handle_mbox_list(struct imsg_mbox_list *, struct store_session *);
void	 handle_mbox_subscribe(struct imsg_mbox_name *, struct store_session *);
void	 handle_mbox_unsubscribe(struct imsg_mbox_name *,
		    struct store_session *);
int	 mailbox_name_valid(const char *);
int	 mailbox_open_dir(const char *);
DIR	*opendirat(int, const char *);
void	 cur_snapshot_discard(struct cur_snapshot *);
int	 fetch_walk_paused(struct store_session *);
void	 fetch_walk_resume(struct store_session *);
void	 fetch_walk_abort(struct store_session *);
void	 fetch_walk_parser(struct store_session *, int);
void	 fetch_walk_parsed(struct store_session *, int,
		    const struct imsg_parser_rep *, char *);
int	 search_walk_paused(struct store_session *);
void	 search_walk_abort(struct store_session *);
void	 search_walk_parser(struct store_session *, int);
void	 search_walk_parsed(struct store_session *, int,
		    const struct imsg_parser_rep *, char *);
int	 search_op_content(int);
int	 search_match(int, const char *, const struct imsg_parser_leaf *,
		    uint32_t, const char *, char **, uint32_t *);
int	 header_next_field(const char *, size_t, size_t *, const char **,
		    size_t *, const char **, size_t *);
size_t	 address_uncomment(char *, size_t);
int	 address_split(char *, size_t, struct address *);
int	 address_list_next(char *, size_t, size_t *, int *, char **,
		    size_t *);
int	 parser_ready(void);
int	 parser_send(struct store_session *, const struct parser_ask *);
void	 parser_cancel(struct store_session *);
int	 locate_message_file(struct cur_snapshot *, int, const char *,
		    off_t *, char *, size_t);
int	 open_message_file(struct cur_snapshot *, int, const char *);
int	 read_message_header(struct cur_snapshot *, int, const char *,
		    char **, uint32_t *);
int	 read_header_from_fd(int, const char *, char **, uint32_t *);
int	 read_body_from_fd(int, const char *, int, size_t,
		    const char *,
		    char **, uint32_t *);
int	 read_message_header_fields(int, const char *, const char *,
		    int,
		    char **, uint32_t *);
void	 build_flags_string(const char *, const char *, char *,
		    size_t);
int	 extract_header_field(const char *, size_t, const char *,
		    char **, size_t *);
int	 envbuf_append(char *, size_t, size_t *, const char *, size_t);
int	 envbuf_append_str(char *, size_t, size_t *, const char *);
int	 envbuf_append_nstring(char *, size_t, size_t *, const char *,
		    size_t);
int	 build_envelope(int, const char *, char **, uint32_t *);
int	 find_header_body_split(const char *, size_t, size_t *);
int	 mime_read_token_or_qstring(const char *, size_t, size_t *,
		    char *, size_t);
void	 parse_content_type(const char *, size_t, struct content_type *);
int	 content_type_params(const char *, size_t, char *, size_t, size_t *);
int	 split_multipart(const char *, size_t, const char *,
		    size_t *, size_t *, int *, int);
int	 build_bodystructure(int, const char *, char **, uint32_t *);
int	 parse_section_part(const char *, int *, int);
void	 partial_range(int, uint32_t, uint32_t, uint64_t *, uint64_t *);
int	 extract_mime_part(int, const char *, const int *, int,
		    uint64_t *, uint64_t *);
int	 message_body_range(struct cur_snapshot *, int, const char *, int,
		    uint64_t *, uint64_t *, int *);

#define STORE_INDEX_LINE_MAX	1024
#define STORE_READ_BLOCK	65536

/* A fixed bound, not a configuration option. */
#define PCACHE_BYTES_MAX	((size_t)4 * 1024 * 1024)

#define PCACHE_ENVELOPE		0
#define PCACHE_BODYSTRUCTURE	1
#define PCACHE_NITEMS		2

const char	*pcache_get(const char *, uint32_t, uint32_t, const char *,
		    int, uint32_t *);
void	 pcache_put(const char *, uint32_t, uint32_t, const char *, int,
		    const char *, uint32_t);
void	 pcache_drop_uid(const char *, uint32_t);
void	 pcache_drop_mailbox(const char *);
void	 pcache_check_mailbox(const char *, uint32_t);
void	 pcache_log(void);

/*
 * The index is opened after the lock.  Initialise with INDEX_LOCK_INIT.
 */
struct index_lock {
	int	lockfd;
	int	fd;
};

#define INDEX_LOCK_INIT	{ -1, -1 }

#define INDEX_LOCK_OK	0
#define INDEX_LOCK_BUSY	1
#define INDEX_LOCK_ERR	(-1)

int	 index_load(int, struct mbox_index *);
int	 index_append(struct mbox_index *, uint32_t, const char *);
int	 index_save(int, const struct mbox_index *);
void	 index_free(struct mbox_index *);
int	 index_parse_line(const char *, struct index_rec *);
int	 index_field_valid(const char *);	/* No colon, CR or LF */
int	 index_basename_valid(const char *);	/* Safe in a new/ path */
uint32_t index_max_uid(struct mbox_index *);
void	 send_vanished_range(const struct mbox_index *, uint32_t, uint32_t,
		    struct store_session *);
uint32_t seqset_resolve(const struct seq_range *, uint32_t, uint32_t, int,
		    struct seq_range[SEQSET_MAX_RANGES]);
int	 seqset_contains(const struct seq_range *, uint32_t, uint32_t);
uint32_t seqset_max_hi(const struct seq_range *, uint32_t);

/* PAST_END is valid only because scans ascend. */
enum seqset_pos {
	SEQSET_PAST_END,
	SEQSET_SKIP,
	SEQSET_MATCH
};

enum seqset_pos	 seqset_position(const struct seq_range *, uint32_t, uint32_t,
		    int, uint32_t, uint32_t);
int	 refresh_index(int, struct mbox_index *, int);
void	 idle_probe_reset(struct store_session *);
void	 idle_baseline_reset(struct store_session *);
int	 index_lock_acquire(int, struct index_lock *, int);
void	 index_lock_release(struct index_lock *);
void	 handle_mbox_idle_refresh(struct store_session *);
void	 idle_baseline_seed(struct store_session *, const struct mbox_index *);
int	 view_sync(struct store_session *, const struct mbox_index *, int);
void	 view_resolve(const struct store_session *, const struct seq_range *,
		    uint32_t, struct seq_range *, uint32_t *, int *);
int	 saved_resolve(const struct store_session *,
		    const struct seq_range *, uint32_t, struct seq_range *,
		    uint32_t *, int *, int *);
uint32_t view_seqno(const struct store_session *, uint32_t, uint32_t);
int	 view_names_ghost(const struct store_session *,
		    const struct mbox_index *, const struct seq_range *,
		    uint32_t);
int	 send_expunged(struct store_session *, uint32_t, uint32_t);
void	 qresync_send_resync(const struct imsg_mbox_select *,
		    const struct seq_range *, uint32_t, struct mbox_index *,
		    struct store_session *);

const char	*append_hostname(void);
int		 ensure_maildir_dirs(int, const char *);
int		 store_space_ok(int);
uint32_t	 letters_to_sysflags(const char *);
int		 merge_keywords(int, const char *, const char *, char *,
		    size_t);
int64_t		 parse_maildir_timestamp(const char *);
void		 sysflags_to_letters(uint32_t, char *, size_t);

#endif
