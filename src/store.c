#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>

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
#include "mboxname.h"
#include "store_internal.h"

static TAILQ_HEAD(, store_session)	 sessions =
				    TAILQ_HEAD_INITIALIZER(sessions);

static struct imsgev	 parent_iev;

static int		 parent_gone;

static void		 store_parent_dispatch(int, short, void *);
static void		 store_attach(uint32_t, int);
static void		 store_detach(struct store_session *);
static void		 store_end(struct store_session *);
static __dead void	 store_exit(void);

/* Serial requests, so a failure names one message. */
static struct imsgev	 parser_iev;
static int		 parser_up;	/* Channel open */
static int		 parser_wanted;	/* Asked the parent, no answer yet */
static uint32_t		 parser_last;
static struct event	 parser_idle_ev;
static struct event	 parser_wait_ev;
static struct event	 parser_deadline_ev;

/* The request out, with session 0 once unwanted. */
static struct {
	char		 basename[NAME_MAX + 1];
	const char	*label;
	uint32_t	 session;
	uint32_t	 type;
	uint32_t	 id;
	uint32_t	 maxlen;
	int		 active;
	int		 fd;
} parser_pending;

/* Kept here, so a parser cannot clear a strike. */
#define PARSER_STRIKE_SLOTS	32
static struct {
	char	 basename[NAME_MAX + 1];
	int	 count;
} parser_strikes[PARSER_STRIKE_SLOTS];
static size_t		 parser_strike_next;

static void	 parser_dispatch(int, short, void *);
static void	 parser_reply(struct imsg *);
static int	 parser_reply_check(const struct imsg_parser_rep *,
		    struct ibuf *, char **);
static void	 parser_done(int, const struct imsg_parser_rep *, char *);
static void	 parser_lost(int);
static void	 parser_deadline(int, short, void *);
static void	 parser_drop(void);
static void	 parser_fail(const char *);
static void	 parser_install(int);
static void	 parser_give_up(void);
static void	 parser_walks(int);
static void	 parser_idle(int, short, void *);
static void	 parser_wait_expired(int, short, void *);
static int	 parser_struck_out(const char *);

static int	 parser_reply_safe(const char *, size_t);
static int	 parser_reply_valid(uint32_t, const char *, size_t,
		    uint32_t);
static int	 parser_literal_safe(const char *, size_t);
static int	 parser_extent_safe(uint64_t, uint64_t, uint64_t);
static int	 extent_has_nul(int, uint64_t, uint64_t);

static int	 imsg_field_valid(const char *, size_t, const char *);

static void		 store_dispatch(int, short, void *);
static void		 deferred_retry(int, short, void *);
static void		 deferred_answer_busy_for(uint32_t,
		    struct store_session *);
static int		 search_nodes_valid(const struct search_node *,
		    uint32_t, uint32_t);
static void		*recv_trailing_array(struct ibuf *, const char *,
		    uint32_t, uint32_t, size_t, int *);
static int		 deferred_expired(struct store_session *);
static void		 deferred_give_up(struct store_session *);
static void		 deferred_arm(struct store_session *);
static void		 defer_command(uint32_t, const void *, size_t,
		    const void *, uint32_t, uint32_t, size_t,
		    struct store_session *);
static int		 require_mailbox_selected(struct store_session *,
		    const char *);
static struct seq_range	*recv_ranges(struct ibuf *, const char *, uint32_t,
		    int *);
static int		 ranges_required(uint32_t, const char *);
static void		 ranged_done(struct store_session *, uint32_t,
		    const void *, size_t, struct seq_range *, uint32_t, int);

uint32_t		 append_counter;
uint32_t		 bodystructure_read_max;
uint64_t		 append_max;
uint32_t		 lock_timeout_secs;
int			 maildir_root_fd = -1;

__dead void
store_main(void)
{
	struct imsg_store_init	 init;
	struct imsgbuf		 ibuf3;
	struct imsg		 imsg;
	gid_t			 gid;
	char			 unveil_path[sizeof(init.maildir) + 1];
	int			 n, ret;

	imsgev_ibuf_init(&ibuf3, 3);

	for (;;) {
		if ((n = imsgbuf_get(&ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n != 0)
			break;
		if ((n = imsgbuf_read(&ibuf3)) == -1)
			fatal("imsgbuf_read");
		if (n == 0)
			fatalx("parent closed channel before INIT");
	}
	if (imsg_get_type(&imsg) != IMSG_STORE_INIT)
		fatalx("expected IMSG_STORE_INIT, got %d",
		    imsg_get_type(&imsg));
	if (imsg_get_data(&imsg, &init, sizeof(init)) == -1)
		fatalx("bad IMSG_STORE_INIT payload");
	imsg_free(&imsg);

	bodystructure_read_max = init.bodystructure_read_max;
	append_max = init.append_max;
	lock_timeout_secs = init.lock_timeout_secs;

	/* These reach chroot(2), so check their NUL termination. */
	if (!imsg_field_valid(init.spool_root, sizeof(init.spool_root),
	    "IMSG_STORE_INIT.spool_root") ||
	    !imsg_field_valid(init.maildir, sizeof(init.maildir),
	    "IMSG_STORE_INIT.maildir"))
		fatalx("malformed IMSG_STORE_INIT payload");

	if (chroot(init.spool_root) == -1)
		fatal("chroot %s", init.spool_root);
	if (chdir("/") == -1)
		fatal("chdir /");

	gid = init.gid;
	if (setgroups(1, &gid) == -1 ||
	    setresgid(init.gid, init.gid, init.gid) == -1 ||
	    setresuid(init.uid, init.uid, init.uid) == -1)
		fatal("cannot drop privileges to uid %u gid %u", init.uid,
		    init.gid);

	setproctitle("store uid %u", (unsigned int)init.uid);

	/* Confine before the ack, so a failure is reported. */
	ret = snprintf(unveil_path, sizeof(unveil_path), "/%s",
	    init.maildir);
	if (ret < 0 || (size_t)ret >= sizeof(unveil_path))
		fatalx("maildir path too long: %s", init.maildir);
	if (unveil(unveil_path, "rwc") == -1)
		fatal("unveil %s", unveil_path);
	if (chdir(unveil_path) == -1)
		fatal("chdir %s", unveil_path);

	/* Lookups relative to this descriptor stay under unveil(2). */
	if ((maildir_root_fd = open(".", O_RDONLY | O_DIRECTORY)) == -1)
		fatal("open maildir root");

	if (unveil(NULL, NULL) == -1)
		fatal("unveil lock");

	setup_recv_done_and_ack(&ibuf3);

	event_init();
	evtimer_set(&parser_idle_ev, parser_idle, NULL);
	evtimer_set(&parser_wait_ev, parser_wait_expired, NULL);
	evtimer_set(&parser_deadline_ev, parser_deadline, NULL);
	imsgev_init_from_ibuf(&parent_iev, &ibuf3, store_parent_dispatch,
	    NULL);

	/* The handshake may have read a later message too. */
	store_parent_dispatch(parent_iev.ibuf.fd, 0, &parent_iev);

	/* FETCH passes the listener a descriptor, hence sendfd. */
	if (pledge("stdio rpath wpath cpath flock recvfd sendfd", NULL) == -1)
		fatal("pledge");

	log_debug("store ready (uid %u, gid %u, spool %s, maildir %s)",
	    init.uid, init.gid, init.spool_root, init.maildir);

	event_dispatch();
	fatalx("exited event loop");
}

static void
store_parent_dispatch(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsg	 imsg;
	int		 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1)
			fatal("imsgbuf_write");
	}
	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0) {
			/* No session can arrive now, so finish those here. */
			log_debug("store: parent closed channel");
			event_del(&iev->ev);
			parent_gone = 1;
			if (TAILQ_EMPTY(&sessions))
				store_exit();
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_SETUP_PEER:
			if (imsg_get_id(&imsg) == 0)
				parser_install(imsg_get_fd(&imsg));
			else
				store_attach(imsg_get_id(&imsg),
				    imsg_get_fd(&imsg));
			break;
		case IMSG_PARSER_NONE:
			if (parser_wanted) {
				log_warnx("store: no parser-worker could be "
				    "started");
				parser_give_up();
			}
			break;
		case IMSG_STORE_EXIT:
			imsg_free(&imsg);
			store_exit();
		default:
			log_debug("%s: unhandled %d", __func__,
			    imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}
	imsgev_rearm_read(iev);
}

static void
store_attach(uint32_t id, int fd)
{
	struct store_session	*ss;
	int			 flags;

	if (fd == -1) {
		log_warnx("session %u: IMSG_SETUP_PEER carried no fd", id);
		return;
	}
	/* A stalled listener must not stall the account. */
	if ((flags = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_warn("session %u: fcntl O_NONBLOCK", id);
		close(fd);
		return;
	}
	TAILQ_FOREACH(ss, &sessions, entry) {
		if (ss->id == id)
			break;
	}
	if (id == 0 || ss != NULL) {
		log_warnx("session %u: attach refused: id 0 or already "
		    "attached", id);
		close(fd);
		return;
	}
	if ((ss = calloc(1, sizeof(*ss))) == NULL) {
		log_warn("session %u: calloc", id);
		close(fd);
		return;
	}
	ss->id = id;
	ss->cur_snap.dfd = -1;		/* Nothing read from cur/ yet. */
	if ((ss->mailbox_dir_fd = mailbox_open_dir("")) == -1) {
		log_warn("session %u: open maildir root", id);
		free(ss);
		close(fd);
		return;
	}
	imsgev_init(&ss->iev, fd, store_dispatch, ss);
	TAILQ_INSERT_TAIL(&sessions, ss, entry);
	log_debug("session %u: attached", id);
}

/*
 * The parser is assumed attackable, so check its reply.
 */
static int
parser_reply_safe(const char *buf, size_t len)
{
	size_t	 i;
	char	 c;
	int	 depth = 0, inquote = 0, escaped = 0;

	if (len < 2 || buf[0] != '(' || buf[len - 1] != ')')
		return (0);

	/* No byte may end the line, quoted or not. */
	for (i = 0; i < len; i++) {
		if (buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\0')
			return (0);
	}

	/* Then framing, so a reply cannot swallow what follows. */
	for (i = 0; i < len; i++) {
		c = buf[i];

		if (escaped) {
			escaped = 0;
			continue;
		}
		if (inquote) {
			if (c == '\\')
				escaped = 1;
			else if (c == '"')
				inquote = 0;
			continue;
		}
		if (c == '"')
			inquote = 1;
		else if (c == '(')
			depth++;
		else if (c == ')' && --depth < 0)
			return (0);
	}

	return (!inquote && !escaped && depth == 0);
}

/*
 * A literal may not hold NUL.
 */
static int
parser_literal_safe(const char *buf, size_t len)
{
	return (len > 0 && len <= FETCH_HEADER_MAX &&
	    memchr(buf, '\0', len) == NULL);
}

static int
parser_reply_valid(uint32_t type, const char *buf, size_t len,
    uint32_t maxlen)
{
	size_t	 i;

	switch (type) {
	case IMSG_PARSER_HEADER_FIELDS:
		return (parser_literal_safe(buf, len));
	case IMSG_PARSER_SEARCH:
		if (len != maxlen)
			return (0);
		for (i = 0; i < len; i++) {
			if (buf[i] != 0 && buf[i] != 1)
				return (0);
		}
		return (1);
	default:
		return (parser_reply_safe(buf, len));
	}
}

static int
parser_extent_safe(uint64_t off, uint64_t len, uint64_t size)
{
	return (off <= size && len <= size - off);
}

static int
extent_has_nul(int fd, uint64_t off, uint64_t len)
{
	ssize_t	 n;
	size_t	 want;
	char	 buf[16384];

	while (len > 0) {
		want = len < sizeof(buf) ? (size_t)len : sizeof(buf);
		if ((n = pread(fd, buf, want, (off_t)off)) == -1) {
			if (errno == EINTR)
				continue;
			return (1);
		}
		if (n == 0 || memchr(buf, '\0', (size_t)n) != NULL)
			return (1);
		off += (uint64_t)n;
		len -= (uint64_t)n;
	}
	return (0);
}

int
parser_send(struct store_session *ss, const struct parser_ask *ask)
{
	struct imsg_parser_req	 none;
	struct imsg_parser_req	*req = ask->req;
	static uint32_t		 reqid;
	struct timeval		 tv;
	struct iovec		 iov[2];
	int			 dupfd;

	if (parser_pending.active)
		fatalx("parser request while one is out");
	if (!parser_up || parser_struck_out(ask->basename))
		return (-1);
	if (req == NULL) {
		memset(&none, 0, sizeof(none));
		req = &none;
	}
	strlcpy(req->basename, ask->basename, sizeof(req->basename));

	if ((dupfd = dup(ask->fd)) == -1) {
		log_warn("dup %s request", ask->label);
		return (-1);
	}
	iov[0].iov_base = req;
	iov[0].iov_len = sizeof(*req);
	iov[1].iov_base = ask->extra;
	iov[1].iov_len = ask->extralen;
	/* Only a successful imsg_composev() owns dupfd. */
	if (imsg_composev(&parser_iev.ibuf, ask->type, ++reqid, 0, dupfd,
	    iov, ask->extra != NULL ? 2 : 1) == -1) {
		log_warn("imsg_composev %s request", ask->label);
		close(dupfd);
		return (-1);
	}

	parser_pending.active = 1;
	parser_pending.session = ss->id;
	parser_pending.type = ask->type;
	parser_pending.id = reqid;
	parser_pending.maxlen = ask->maxlen;
	parser_pending.fd = ask->fd;
	parser_pending.label = ask->label;
	strlcpy(parser_pending.basename, ask->basename,
	    sizeof(parser_pending.basename));
	parser_last = ss->id;

	evtimer_del(&parser_idle_ev);
	tv.tv_sec = PARSER_REPLY_TIMEOUT_SEC;
	tv.tv_usec = 0;
	evtimer_add(&parser_deadline_ev, &tv);
	return (0);
}

void
parser_cancel(struct store_session *ss)
{
	if (parser_pending.active && parser_pending.session == ss->id)
		parser_pending.session = 0;
}

static void
parser_dispatch(int fd, short event, void *arg)
{
	struct imsgev	*iev = &parser_iev;
	struct imsg	 imsg;
	int		 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			/* It never had the request, so count no strike. */
			log_warn("imsgbuf_write (parser)");
			parser_lost(0);
			return;
		}
	}
	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1) {
			log_warn("imsgbuf_read (parser)");
			parser_lost(1);
			return;
		}
		if (n == 0) {
			if (parser_pending.active)
				log_warnx("parser-worker closed its channel, "
				    "message %s", parser_pending.basename);
			parser_lost(1);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			log_warn("imsgbuf_get (parser)");
			parser_lost(1);
			return;
		}
		if (n == 0)
			break;
		parser_reply(&imsg);
		imsg_free(&imsg);
		if (!parser_up)
			return;
	}
	imsgev_rearm_read(iev);
}

static void
parser_reply(struct imsg *imsg)
{
	struct imsg_parser_rep	 rep;
	struct ibuf		 ibuf;
	char			*buf = NULL;
	int			 rc = -1;

	/* Nothing may arrive between requests, so anything ends it. */
	if (!parser_pending.active) {
		parser_drop();
		return;
	}
	if (imsg_get_type(imsg) != parser_pending.type ||
	    imsg_get_id(imsg) != parser_pending.id) {
		log_warnx("unexpected parser reply type %u id %u "
		    "(wanted %u/%u)", imsg_get_type(imsg), imsg_get_id(imsg),
		    parser_pending.type, parser_pending.id);
		return;
	}
	if (imsg_get_ibuf(imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &rep, sizeof(rep)) == -1) {
		log_warnx("bad parser reply header");
		parser_done(-1, NULL, NULL);
		return;
	}
	if (parser_pending.session != 0)
		rc = parser_reply_check(&rep, &ibuf, &buf);
	/* It exits after this reply, so let it go. */
	if (rep.retiring) {
		log_debug("parser-worker retiring");
		parser_drop();
	}
	parser_done(rc, &rep, buf);
}

static int
parser_reply_check(const struct imsg_parser_rep *rep, struct ibuf *ibuf,
    char **bufp)
{
	struct stat	 st;
	char		*buf;

	*bufp = NULL;
	if (rep->found && parser_pending.type == IMSG_PARSER_PART) {
		/* Checked against the file, not the parser's word. */
		if (ibuf_size(ibuf) == 0 &&
		    fstat(parser_pending.fd, &st) == 0 &&
		    parser_extent_safe(rep->part_off, rep->part_len,
		    (uint64_t)st.st_size) &&
		    !extent_has_nul(parser_pending.fd, rep->part_off,
		    rep->part_len))
			return (0);
		goto unsendable;
	}
	if (!rep->found || rep->len == 0 || rep->len > parser_pending.maxlen ||
	    ibuf_size(ibuf) != rep->len)
		return (-1);
	if ((buf = malloc(rep->len)) == NULL) {
		log_warn("malloc %s", parser_pending.label);
		return (-1);
	}
	if (ibuf_get(ibuf, buf, rep->len) == -1) {
		log_warnx("bad parser reply data");
		free(buf);
		return (-1);
	}
	if (!parser_reply_valid(parser_pending.type, buf, rep->len,
	    parser_pending.maxlen)) {
		free(buf);
		goto unsendable;
	}
	*bufp = buf;
	return (0);

unsendable:
	log_warnx("parser %s unsendable, message %s skipped",
	    parser_pending.label, parser_pending.basename);
	return (-1);
}

/*
 * Serve other askers first, then the one that asked.
 */
static void
parser_done(int rc, const struct imsg_parser_rep *rep, char *buf)
{
	struct store_session	*ss;
	struct timeval		 tv;
	uint32_t		 id, type;

	id = parser_pending.session;
	type = parser_pending.type;
	evtimer_del(&parser_deadline_ev);
	memset(&parser_pending, 0, sizeof(parser_pending));
	if (parser_up) {
		tv.tv_sec = PARSER_IDLE_SEC;
		tv.tv_usec = 0;
		evtimer_add(&parser_idle_ev, &tv);
	}
	parser_walks(1);

	TAILQ_FOREACH(ss, &sessions, entry) {
		if (ss->id == id)
			break;
	}
	if (id == 0 || ss == NULL) {
		free(buf);
		return;
	}
	if (type == IMSG_PARSER_SEARCH)
		search_walk_parsed(ss, rc, rep, buf);
	else
		fetch_walk_parsed(ss, rc, rep, buf);
}

static void
parser_lost(int strike)
{
	if (!parser_pending.active) {
		parser_drop();
		return;
	}
	if (strike)
		parser_fail(parser_pending.basename);
	else
		parser_drop();
	parser_done(-1, NULL, NULL);
}

static void
parser_deadline(int fd, short event, void *arg)
{
	log_warnx("parser-worker did not answer within %d seconds, message %s",
	    PARSER_REPLY_TIMEOUT_SEC, parser_pending.basename);
	parser_lost(1);
}

int
parser_ready(void)
{
	struct timeval	 tv;

	if (parser_up)
		return (parser_pending.active ? 0 : 1);
	if (parser_wanted)
		return (0);
	if (parent_gone)
		return (-1);
	if (imsg_compose(&parent_iev.ibuf, IMSG_PARSER_WANT, 0, 0, -1, NULL,
	    0) == -1) {
		log_warn("imsg_compose IMSG_PARSER_WANT");
		return (-1);
	}
	parser_wanted = 1;
	tv.tv_sec = PARSER_REPLY_TIMEOUT_SEC;
	tv.tv_usec = 0;
	evtimer_add(&parser_wait_ev, &tv);
	return (0);
}

/*
 * Closing its channel is what ends the parser.
 */
static void
parser_drop(void)
{
	if (!parser_up)
		return;
	evtimer_del(&parser_idle_ev);
	event_del(&parser_iev.ev);
	close(parser_iev.ibuf.fd);
	imsgbuf_clear(&parser_iev.ibuf);
	parser_up = 0;
}

static void
parser_fail(const char *basename)
{
	size_t	 i;

	parser_drop();
	for (i = 0; i < PARSER_STRIKE_SLOTS; i++) {
		if (parser_strikes[i].count > 0 &&
		    strcmp(parser_strikes[i].basename, basename) == 0)
			break;
	}
	if (i == PARSER_STRIKE_SLOTS) {
		i = parser_strike_next++ % PARSER_STRIKE_SLOTS;
		(void)strlcpy(parser_strikes[i].basename, basename,
		    sizeof(parser_strikes[i].basename));
		parser_strikes[i].count = 0;
	}
	if (++parser_strikes[i].count == PARSER_STRIKES)
		log_warnx("message %s: parser failed %d times, not retried",
		    basename, PARSER_STRIKES);
}

static int
parser_struck_out(const char *basename)
{
	size_t	 i;

	for (i = 0; i < PARSER_STRIKE_SLOTS; i++) {
		if (parser_strikes[i].count >= PARSER_STRIKES &&
		    strcmp(parser_strikes[i].basename, basename) == 0)
			return (1);
	}
	return (0);
}

static void
parser_install(int fd)
{
	struct timeval	 tv;

	if (fd == -1) {
		log_warnx("store: parser IMSG_SETUP_PEER carried no fd");
		return;
	}
	if (parser_up) {
		log_warnx("store: second parser-worker refused");
		close(fd);
		return;
	}
	imsgev_init(&parser_iev, fd, parser_dispatch, NULL);
	parser_up = 1;
	parser_wanted = 0;
	evtimer_del(&parser_wait_ev);
	tv.tv_sec = PARSER_IDLE_SEC;
	tv.tv_usec = 0;
	evtimer_add(&parser_idle_ev, &tv);
	parser_walks(1);
}

static void
parser_give_up(void)
{
	parser_wanted = 0;
	evtimer_del(&parser_wait_ev);
	parser_walks(0);
}

/*
 * Take turns, starting after the last session served.
 */
static void
parser_walks(int ok)
{
	struct store_session	*ss, *first;

	TAILQ_FOREACH(ss, &sessions, entry) {
		if (ss->id == parser_last)
			break;
	}
	first = ss != NULL ? TAILQ_NEXT(ss, entry) : NULL;
	for (ss = first; ss != NULL; ss = TAILQ_NEXT(ss, entry)) {
		fetch_walk_parser(ss, ok);
		search_walk_parser(ss, ok);
	}
	TAILQ_FOREACH(ss, &sessions, entry) {
		if (ss == first)
			break;
		fetch_walk_parser(ss, ok);
		search_walk_parser(ss, ok);
	}
}

static void
parser_idle(int fd, short event, void *arg)
{
	log_debug("store: parser-worker idle, letting it go");
	parser_drop();
}

static void
parser_wait_expired(int fd, short event, void *arg)
{
	log_warnx("store: no parser-worker within %d seconds",
	    PARSER_REPLY_TIMEOUT_SEC);
	parser_give_up();
}

int
mailbox_name_valid(const char *name)
{
	if (memchr(name, '\0', MBOX_NAME_MAX) == NULL) {
		log_warnx("mailbox name not NUL-terminated");
		return (0);
	}

	return (mailbox_name_syntax_ok(name));
}

int
mailbox_open_dir(const char *target)
{
	return (openat(maildir_root_fd, target[0] != '\0' ? target : ".",
	    O_RDONLY | O_DIRECTORY));
}

/*
 * As opendir(3), but relative to dfd.  On failure nothing is left open.
 */
DIR *
opendirat(int dfd, const char *name)
{
	DIR	*dp;
	int	 fd, saved_errno;

	if ((fd = openat(dfd, name, O_RDONLY | O_DIRECTORY)) == -1)
		return (NULL);
	if ((dp = fdopendir(fd)) == NULL) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
	}
	return (dp);
}

static int
imsg_field_valid(const char *field, size_t size, const char *what)
{
	if (memchr(field, '\0', size) != NULL)
		return (1);
	log_warnx("%s not NUL-terminated", what);
	return (0);
}

static int
search_nodes_valid(const struct search_node *nodes, uint32_t nnodes,
    uint32_t poollen)
{
	const struct search_node	*n;
	uint32_t			 i;

	for (i = 0; i < nnodes; i++) {
		n = &nodes[i];
		if (memchr(n->keyword, '\0', sizeof(n->keyword)) == NULL) {
			log_warnx("SEARCH node %u: keyword not NUL-terminated",
			    i);
			return (0);
		}
		if (search_op_content(n->op) && (n->str_off > poollen ||
		    n->str_len > poollen - n->str_off ||
		    n->name_off > poollen ||
		    n->name_len > poollen - n->name_off)) {
			log_warnx("SEARCH node %u: string outside its pool", i);
			return (0);
		}
	}
	return (1);
}

static void *
recv_trailing_array(struct ibuf *ibuf, const char *what, uint32_t count,
    uint32_t maxcount, size_t elemsize, int *ok_out)
{
	size_t	 bodylen;
	void	*out;

	*ok_out = 0;

	if (count > maxcount) {
		log_warnx("%s count %u over the allowed maximum %u", what,
		    count, maxcount);
		return (NULL);
	}
	bodylen = ibuf_size(ibuf);
	if (bodylen != (size_t)count * elemsize) {
		log_warnx("%s length mismatch (header %u elements, imsg %zu "
		    "bytes)", what, count, bodylen);
		return (NULL);
	}
	*ok_out = 1;
	if (bodylen == 0)
		return (NULL);
	if ((out = malloc(bodylen)) == NULL) {
		log_warn("malloc %s elements", what);
		*ok_out = 0;
		return (NULL);
	}
	if (ibuf_get(ibuf, out, bodylen) == -1) {
		log_warnx("bad %s (elements)", what);
		free(out);
		*ok_out = 0;
		return (NULL);
	}
	return (out);
}

/* Doubling makes waiting cheap, and the cap bounds latency. */
#define LOCK_RETRY_FIRST_MS	50
#define LOCK_RETRY_CAP_MS	250

static int
deferred_expired(struct store_session *ss)
{
	struct store_deferred	*d = &ss->deferred;
	struct timespec		 now;

	if (lock_timeout_secs == 0)
		return (0);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		log_warn("session %u: clock_gettime", ss->id);
		return (1);	/* No clock, so stop waiting. */
	}
	return (timespeccmp(&now, &d->give_up_at, >=));
}

/*
 * Answer one command INUSE, having changed nothing.
 */
static void
deferred_answer_busy_for(uint32_t type, struct store_session *ss)
{
	struct imsgev			*iev = &ss->iev;
	struct imsg_mbox_result		 result;
	struct imsg_mbox_selected	 selected;
	struct imsg_mbox_status_result	 status;
	struct imsg_mbox_appended	 appended;
	const void			*data = NULL;
	size_t				 len = 0;
	uint32_t			 rtype = 0;

	/* A SAVE answered NO empties the saved result. */
	if (type == IMSG_MBOX_SEARCH &&
	    (ss->deferred.req.search.return_opts & SEARCH_RETURN_SAVE))
		ss->nsaved = 0;
	switch (type) {
	case IMSG_MBOX_STORE:
	case IMSG_MBOX_EXPUNGE:
	case IMSG_MBOX_FETCH:
	case IMSG_MBOX_SEARCH:
	case IMSG_MBOX_COPY:
	case IMSG_MBOX_MOVE:
		memset(&result, 0, sizeof(result));
		result.error = MBOX_OP_ERR_BUSY;
		rtype = IMSG_MBOX_RESULT;
		data = &result;
		len = sizeof(result);
		break;
	case IMSG_MBOX_SELECT:
		memset(&selected, 0, sizeof(selected));
		selected.error = MBOX_OP_ERR_BUSY;
		rtype = IMSG_MBOX_SELECTED;
		data = &selected;
		len = sizeof(selected);
		break;
	case IMSG_MBOX_STATUS:
		memset(&status, 0, sizeof(status));
		status.error = MBOX_OP_ERR_BUSY;
		rtype = IMSG_MBOX_STATUS_RESULT;
		data = &status;
		len = sizeof(status);
		break;
	case IMSG_MBOX_APPEND_END:
		/* The tmp/ file and descriptors go with the command. */
		append_abort(ss);
		memset(&appended, 0, sizeof(appended));
		appended.error = MBOX_OP_ERR_BUSY;
		rtype = IMSG_MBOX_APPENDED;
		data = &appended;
		len = sizeof(appended);
		break;
	default:
		fatalx("session %u: no busy reply for imsg %u", ss->id,
		    type);
	}
	if (data != NULL && imsg_compose(&iev->ibuf, rtype, 0, 0, -1, data,
	    len) == -1)
		log_warn("session %u: imsg_compose busy reply %u", ss->id,
		    rtype);
	/* Composed outside the dispatcher, so arm EV_WRITE here. */
	imsgev_rearm_read(iev);
}

static void
deferred_give_up(struct store_session *ss)
{
	log_debug("session %u: gave up waiting for the index lock after "
	    "%u seconds", ss->id, lock_timeout_secs);
	deferred_answer_busy_for(ss->deferred.type, ss);
	ss->deferred.active = 0;
}

static void
deferred_arm(struct store_session *ss)
{
	struct store_deferred	*d = &ss->deferred;
	struct timeval		 tv;

	tv.tv_sec = d->wait_ms / 1000;
	tv.tv_usec = (suseconds_t)(d->wait_ms % 1000) * 1000;
	evtimer_set(&d->ev, deferred_retry, ss);
	if (evtimer_add(&d->ev, &tv) == -1) {
		log_warnx("session %u: evtimer_add (lock retry), answering "
		    "busy", ss->id);
		deferred_give_up(ss);
		return;
	}
	if (d->wait_ms < LOCK_RETRY_CAP_MS) {
		d->wait_ms *= 2;
		if (d->wait_ms > LOCK_RETRY_CAP_MS)
			d->wait_ms = LOCK_RETRY_CAP_MS;
	}
}

static void
deferred_retry(int fd, short event, void *arg)
{
	struct store_session	*ss = arg;
	struct store_deferred	*d = &ss->deferred;
	int			 again;

	switch (d->type) {
	case IMSG_MBOX_STORE:
		again = handle_mbox_store(&d->req.store, d->elts.ranges,
		    d->nelts, ss);
		break;
	case IMSG_MBOX_EXPUNGE:
		again = handle_mbox_expunge(&d->req.expunge,
		    d->nelts > 0 ? d->elts.ranges : NULL, d->nelts, ss);
		break;
	case IMSG_MBOX_FETCH:
		again = handle_mbox_fetch(&d->req.fetch, d->elts.ranges,
		    d->nelts, ss);
		break;
	case IMSG_MBOX_SEARCH:
		again = handle_mbox_search(&d->req.search,
		    d->nelts > 0 ? d->elts.nodes : NULL, d->nelts, ss);
		break;
	case IMSG_MBOX_SELECT:
		again = handle_mbox_select(&d->req.select,
		    d->nelts > 0 ? d->elts.ranges : NULL, d->nelts, ss);
		break;
	case IMSG_MBOX_STATUS:
		again = handle_mbox_status(&d->req.status, ss);
		break;
	case IMSG_MBOX_COPY:
		again = handle_mbox_copy(&d->req.copy, d->elts.ranges,
		    d->nelts, ss);
		break;
	case IMSG_MBOX_MOVE:
		again = handle_mbox_move(&d->req.copy, d->elts.ranges,
		    d->nelts, ss);
		break;
	case IMSG_MBOX_APPEND_END:
		/* The APPEND holds its state, not a saved request. */
		again = handle_mbox_append_end(ss);
		break;
	default:
		fatalx("session %u: deferred imsg %u", ss->id, d->type);
	}
	if (!again) {
		d->active = 0;
		if (!fetch_walk_paused(ss) && !search_walk_paused(ss))
			cur_snapshot_discard(&ss->cur_snap);
		imsgev_rearm_read(&ss->iev);
		return;
	}
	if (deferred_expired(ss))
		deferred_give_up(ss);
	else
		deferred_arm(ss);
}

static void
defer_command(uint32_t type, const void *req, size_t reqlen,
    const void *elts, uint32_t nelts, uint32_t maxelts, size_t eltlen,
    struct store_session *ss)
{
	struct store_deferred	*d = &ss->deferred;
	struct timespec		 now;

	if (d->active) {
		log_warnx("session %u: a second deferred command, refused",
		    ss->id);
		deferred_answer_busy_for(type, ss);
		return;
	}
	if (reqlen > sizeof(d->req) || nelts > maxelts ||
	    (size_t)nelts * eltlen > sizeof(d->elts))
		fatalx("session %u: imsg %u too large to defer", ss->id,
		    type);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		log_warn("session %u: clock_gettime", ss->id);
		now.tv_sec = 0;
		now.tv_nsec = 0;
	}
	d->active = 1;
	d->type = type;
	if (reqlen > 0)
		memcpy(&d->req, req, reqlen);
	if (nelts > 0)
		memcpy(&d->elts, elts, (size_t)nelts * eltlen);
	d->nelts = nelts;
	d->give_up_at = now;
	d->give_up_at.tv_sec += lock_timeout_secs;
	d->wait_ms = LOCK_RETRY_FIRST_MS;

	log_debug("session %u: index lock held elsewhere, waiting up to "
	    "%u seconds", ss->id, lock_timeout_secs);
	deferred_arm(ss);
}

/*
 * Checked here, never trusted from the listener.
 */
static int
require_mailbox_selected(struct store_session *ss, const char *what)
{
	if (ss->mailbox_selected)
		return (1);
	log_warnx("session %u: %s before IMSG_MBOX_SELECT, refused",
	    ss->id, what);
	return (0);
}

static struct seq_range *
recv_ranges(struct ibuf *ibuf, const char *what, uint32_t nranges, int *ok)
{
	return (recv_trailing_array(ibuf, what, nranges, SEQSET_MAX_RANGES,
	    sizeof(struct seq_range), ok));
}

static int
ranges_required(uint32_t nranges, const char *what)
{
	if (nranges != 0)
		return (1);
	log_warnx("%s requires at least one range", what);
	return (0);
}

/*
 * A handler return of 1 defers the command.
 */
static void
ranged_done(struct store_session *ss, uint32_t type, const void *req,
    size_t reqlen, struct seq_range *ranges, uint32_t nranges, int rc)
{
	if (rc == 1)
		defer_command(type, req, reqlen, ranges, nranges,
		    SEQSET_MAX_RANGES, sizeof(*ranges), ss);
	free(ranges);
}

static void
store_dispatch(int fd, short event, void *arg)
{
	struct store_session	*ss = arg;
	struct imsgev		*iev = &ss->iev;
	struct imsg		 imsg;
	struct ibuf		 ibuf;
	union mbox_request	 u;
	struct seq_range	*ranges;
	struct search_node	*nodes;
	char			 buf[MAX_IMSGSIZE];
	size_t			 len;
	int			 n, ok, rc;

	/* A failure here ends this session, not the process. */
	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			log_warn("session %u: imsgbuf_write", ss->id);
			store_end(ss);
			return;
		}
		/* A FETCH paused for a full queue resumes here. */
		fetch_walk_resume(ss);
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1) {
			log_warn("session %u: imsgbuf_read", ss->id);
			store_end(ss);
			return;
		}
		if (n == 0) {
			/* A closed listener counts as IMSG_STORE_SHUTDOWN. */
			store_end(ss);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			log_warn("session %u: imsgbuf_get", ss->id);
			store_end(ss);
			return;
		}
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_STORE_SHUTDOWN:
			imsg_free(&imsg);
			store_end(ss);
			return;
		case IMSG_MBOX_SELECT:
			if (!recv_header(&imsg, &ibuf, &u.select,
			    sizeof(u.select), "IMSG_MBOX_SELECT"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_SELECT",
			    u.select.qresync_nranges, &ok);
			if (!ok)
				break;
			/* A failed SELECT deselects, so clear first. */
			ss->mailbox_selected = 0;
			rc = handle_mbox_select(&u.select, ranges,
			    u.select.qresync_nranges, ss);
			ranged_done(ss, IMSG_MBOX_SELECT, &u.select,
			    sizeof(u.select), ranges, u.select.qresync_nranges,
			    rc);
			break;
		case IMSG_MBOX_FETCH:
			if (!require_mailbox_selected(ss, "IMSG_MBOX_FETCH") ||
			    !recv_header(&imsg, &ibuf, &u.fetch,
			    sizeof(u.fetch), "IMSG_MBOX_FETCH") ||
			    !imsg_field_valid(u.fetch.header_fields,
			    sizeof(u.fetch.header_fields),
			    "IMSG_MBOX_FETCH.header_fields") ||
			    !imsg_field_valid(u.fetch.section_part,
			    sizeof(u.fetch.section_part),
			    "IMSG_MBOX_FETCH.section_part") ||
			    !ranges_required(u.fetch.nranges,
			    "IMSG_MBOX_FETCH"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_FETCH",
			    u.fetch.nranges, &ok);
			if (!ok)
				break;
			rc = handle_mbox_fetch(&u.fetch, ranges,
			    u.fetch.nranges, ss);
			ranged_done(ss, IMSG_MBOX_FETCH, &u.fetch,
			    sizeof(u.fetch), ranges, u.fetch.nranges, rc);
			break;
		case IMSG_MBOX_STORE:
			if (!require_mailbox_selected(ss, "IMSG_MBOX_STORE") ||
			    !recv_header(&imsg, &ibuf, &u.store,
			    sizeof(u.store), "IMSG_MBOX_STORE") ||
			    !imsg_field_valid(u.store.keywords,
			    sizeof(u.store.keywords),
			    "IMSG_MBOX_STORE.keywords") ||
			    !ranges_required(u.store.nranges,
			    "IMSG_MBOX_STORE"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_STORE",
			    u.store.nranges, &ok);
			if (!ok)
				break;
			rc = handle_mbox_store(&u.store, ranges,
			    u.store.nranges, ss);
			ranged_done(ss, IMSG_MBOX_STORE, &u.store,
			    sizeof(u.store), ranges, u.store.nranges, rc);
			break;
		case IMSG_MBOX_EXPUNGE:
			if (!require_mailbox_selected(ss,
			    "IMSG_MBOX_EXPUNGE") ||
			    !recv_header(&imsg, &ibuf, &u.expunge,
			    sizeof(u.expunge), "IMSG_MBOX_EXPUNGE"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_EXPUNGE",
			    u.expunge.nranges, &ok);
			if (!ok)
				break;
			rc = handle_mbox_expunge(&u.expunge, ranges,
			    u.expunge.nranges, ss);
			ranged_done(ss, IMSG_MBOX_EXPUNGE, &u.expunge,
			    sizeof(u.expunge), ranges, u.expunge.nranges, rc);
			break;
		case IMSG_MBOX_IDLE_REFRESH:
			if (imsg_get_len(&imsg) != 0) {
				log_warnx("bad IMSG_MBOX_IDLE_REFRESH");
				break;
			}
			/* Answered even if refused, as the listener waits. */
			(void)require_mailbox_selected(ss,
			    "IMSG_MBOX_IDLE_REFRESH");
			handle_mbox_idle_refresh(ss);
			break;
		case IMSG_MBOX_APPEND:
			/* No reply, since the literal follows regardless. */
			if (recv_fixed(&imsg, &u.append, sizeof(u.append),
			    "IMSG_MBOX_APPEND") &&
			    imsg_field_valid(u.append.keywords,
			    sizeof(u.append.keywords),
			    "IMSG_MBOX_APPEND.keywords"))
				handle_mbox_append_begin(ss, &u.append);
			break;
		case IMSG_MBOX_APPEND_DATA:
			len = imsg_get_len(&imsg);
			if (len == 0 || len > sizeof(buf) ||
			    imsg_get_buf(&imsg, buf, len) == -1) {
				log_warnx("bad IMSG_MBOX_APPEND_DATA");
				break;
			}
			handle_mbox_append_data(ss, buf, len);
			break;
		case IMSG_MBOX_APPEND_END:
			if (handle_mbox_append_end(ss) == 1)
				defer_command(IMSG_MBOX_APPEND_END, NULL, 0,
				    NULL, 0, 0, 0, ss);
			break;
		case IMSG_MBOX_SEARCH:
			if (!require_mailbox_selected(ss, "IMSG_MBOX_SEARCH") ||
			    !recv_header(&imsg, &ibuf, &u.search,
			    sizeof(u.search), "IMSG_MBOX_SEARCH"))
				break;
			if (u.search.poollen > sizeof(u.search.pool)) {
				log_warnx("bad IMSG_MBOX_SEARCH (header)");
				break;
			}
			nodes = recv_trailing_array(&ibuf, "IMSG_MBOX_SEARCH",
			    u.search.nnodes, SEARCH_PROGRAM_MAX_NODES,
			    sizeof(struct search_node), &ok);
			if (!ok)
				break;
			if (nodes != NULL && !search_nodes_valid(nodes,
			    u.search.nnodes, u.search.poollen)) {
				free(nodes);
				break;
			}
			if (handle_mbox_search(&u.search, nodes,
			    u.search.nnodes, ss) == 1)
				defer_command(IMSG_MBOX_SEARCH, &u.search,
				    sizeof(u.search), nodes, u.search.nnodes,
				    SEARCH_PROGRAM_MAX_NODES, sizeof(*nodes),
				    ss);
			free(nodes);
			break;
		case IMSG_MBOX_SAVED_CLEAR:
			if (imsg_get_len(&imsg) != 0) {
				log_warnx("bad IMSG_MBOX_SAVED_CLEAR");
				break;
			}
			ss->nsaved = 0;
			break;
		case IMSG_MBOX_STATUS:
			if (recv_fixed(&imsg, &u.status, sizeof(u.status),
			    "IMSG_MBOX_STATUS") &&
			    handle_mbox_status(&u.status, ss) == 1)
				defer_command(IMSG_MBOX_STATUS, &u.status,
				    sizeof(u.status), NULL, 0, 0, 0, ss);
			break;
		case IMSG_MBOX_COPY:
			if (!require_mailbox_selected(ss, "IMSG_MBOX_COPY") ||
			    !recv_header(&imsg, &ibuf, &u.copy,
			    sizeof(u.copy), "IMSG_MBOX_COPY") ||
			    !ranges_required(u.copy.nranges, "IMSG_MBOX_COPY"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_COPY",
			    u.copy.nranges, &ok);
			if (!ok)
				break;
			rc = handle_mbox_copy(&u.copy, ranges, u.copy.nranges,
			    ss);
			ranged_done(ss, IMSG_MBOX_COPY, &u.copy, sizeof(u.copy),
			    ranges, u.copy.nranges, rc);
			break;
		case IMSG_MBOX_MOVE:
			if (!require_mailbox_selected(ss, "IMSG_MBOX_MOVE") ||
			    !recv_header(&imsg, &ibuf, &u.copy,
			    sizeof(u.copy), "IMSG_MBOX_MOVE") ||
			    !ranges_required(u.copy.nranges, "IMSG_MBOX_MOVE"))
				break;
			ranges = recv_ranges(&ibuf, "IMSG_MBOX_MOVE",
			    u.copy.nranges, &ok);
			if (!ok)
				break;
			rc = handle_mbox_move(&u.copy, ranges, u.copy.nranges,
			    ss);
			ranged_done(ss, IMSG_MBOX_MOVE, &u.copy, sizeof(u.copy),
			    ranges, u.copy.nranges, rc);
			break;
		case IMSG_MBOX_LIST:
			if (recv_fixed(&imsg, &u.list, sizeof(u.list),
			    "IMSG_MBOX_LIST"))
				handle_mbox_list(&u.list, ss);
			break;
		case IMSG_MBOX_CREATE:
			if (recv_fixed(&imsg, &u.name, sizeof(u.name),
			    "IMSG_MBOX_CREATE"))
				handle_mbox_create(&u.name, ss);
			break;
		case IMSG_MBOX_DELETE:
			if (recv_fixed(&imsg, &u.name, sizeof(u.name),
			    "IMSG_MBOX_DELETE"))
				handle_mbox_delete(&u.name, ss);
			break;
		case IMSG_MBOX_RENAME:
			if (recv_fixed(&imsg, &u.rename, sizeof(u.rename),
			    "IMSG_MBOX_RENAME"))
				handle_mbox_rename(&u.rename, ss);
			break;
		case IMSG_MBOX_SUBSCRIBE:
			if (recv_fixed(&imsg, &u.name, sizeof(u.name),
			    "IMSG_MBOX_SUBSCRIBE"))
				handle_mbox_subscribe(&u.name, ss);
			break;
		case IMSG_MBOX_UNSUBSCRIBE:
			if (recv_fixed(&imsg, &u.name, sizeof(u.name),
			    "IMSG_MBOX_UNSUBSCRIBE"))
				handle_mbox_unsubscribe(&u.name, ss);
			break;
		default:
			log_debug("%s: unhandled %d (session %u)", __func__,
			    imsg_get_type(&imsg), ss->id);
			break;
		}
		imsg_free(&imsg);

		/* The cur/ snapshot does not outlive the command. */
		if (!fetch_walk_paused(ss) && !search_walk_paused(ss))
			cur_snapshot_discard(&ss->cur_snap);
	}
	imsgev_rearm_read(iev);
}

static void
store_detach(struct store_session *ss)
{
	log_debug("session %u: detached", ss->id);
	if (ss->deferred.active)
		evtimer_del(&ss->deferred.ev);
	fetch_walk_abort(ss);
	search_walk_abort(ss);
	append_abort(ss);
	cur_snapshot_discard(&ss->cur_snap);
	idle_baseline_reset(ss);
	if (ss->mailbox_dir_fd != -1)
		close(ss->mailbox_dir_fd);
	event_del(&ss->iev.ev);
	close(ss->iev.ibuf.fd);
	imsgbuf_clear(&ss->iev.ibuf);
	TAILQ_REMOVE(&sessions, ss, entry);
	free(ss);
}

static void
store_end(struct store_session *ss)
{
	store_detach(ss);
	if (parent_gone && TAILQ_EMPTY(&sessions))
		store_exit();
}

static __dead void
store_exit(void)
{
	struct store_session	*ss;

	while ((ss = TAILQ_FIRST(&sessions)) != NULL)
		store_detach(ss);
	pcache_log();
	log_debug("store: shutting down");
	exit(0);
}
