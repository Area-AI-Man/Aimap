/*
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "aimap.h"
#include "log.h"

/* Only a store slower than this is torn down. */
#define STORE_SETUP_TIMEOUT_SEC	10
/* SIGTERM waits this long before killing children. */
#define SHUTDOWN_TIMEOUT_SEC	5
#define MAX_IMSG_DATA_SIZE	(MAX_IMSGSIZE - IMSG_HEADER_SIZE)

/* Upper bound of connections max, and a backstop. */
#define OPEN_SESSION_MAX	4096

/* The pause of accept(2) when out of descriptors. */
#define ACCEPT_PAUSE_SEC	1

struct child {
	pid_t				 pid;
	enum aimap_proc_type	 type;
	struct imsgev			 iev;
	TAILQ_ENTRY(child)		 entry;
};

/* One per account, shared by its sessions. */
struct store_child {
	uint32_t			 session_id;
	uid_t				 uid;
	gid_t				 gid;
	char				 maildir[STORE_MAILDIR_MAX];
	unsigned int			 nsessions;
	int				 exiting;
	pid_t				 pid;
	pid_t				 parser_pid;
	struct imsgev			 iev;
	int				 pending;
	struct event			 timeout_ev;
	TAILQ_ENTRY(store_child)	 entry;
};

struct open_session {
	uint32_t			 session_id;
	int				 authenticated;
	struct imsgev			*listener_iev;
	struct imsgev			*auth_iev;
	pid_t				 listener_pid;
	pid_t				 auth_pid;
	struct store_child		*store;
	struct sockaddr_storage		 peer;
	TAILQ_ENTRY(open_session)	 entry;
};

struct listen_sock {
	struct event	 ev;
	int		 fd;
	int		 implicit_tls;
};

static TAILQ_HEAD(, child)		 children =
				    TAILQ_HEAD_INITIALIZER(children);
static TAILQ_HEAD(, store_child)	 store_children =
				    TAILQ_HEAD_INITIALIZER(store_children);
static TAILQ_HEAD(, open_session)	 open_sessions =
				    TAILQ_HEAD_INITIALIZER(open_sessions);

static struct imsgev		*iev_keymgr;

/* A certificate sent to keymgr, until it answers. */
struct cert_pending {
	uint32_t			 gen;
	uint8_t				*cert;
	size_t				 len;
	TAILQ_ENTRY(cert_pending)	 entry;
};
static TAILQ_HEAD(, cert_pending)	 certs_pending =
				    TAILQ_HEAD_INITIALIZER(certs_pending);
static uint32_t			 keymgr_gen;

/* The certificate listeners are given, matching keymgr's key. */
static uint8_t			*live_cert;
static size_t			 live_cert_len;

static struct aimap_config	*gconf;
static char			 progpath[PATH_MAX];
static char			**saved_argv;
static const char		*conf_path;

static struct event	 ev_sighup, ev_sigterm, ev_sigchld;

static struct listen_sock	 listen_socks[2 * LISTENER_MAX_ADDRS];
static int			 n_listen;

static uint32_t		 next_session_id = 1;

static int		 shutting_down;
static struct event	 ev_shutdown;
/* The accept(2) pause, and connections max reached. */
static struct event	 ev_accept_pause;
static int		 connections_full;

static __dead void		 exec_self_as(const char *);
static pid_t			 fork_child(enum aimap_proc_type,
		    struct imsgev **, void (*)(int, short, void *));
static pid_t			 fork_child_nonfatal(enum aimap_proc_type,
		    struct imsgev **, void (*)(int, short, void *));
static int			 setup_peer_send(struct imsgev *,
		    struct imsgev *, int, const char *, uint32_t);
static void			 setup_done_send(struct imsgev *);
static void			 parent_dispatch_child(int, short, void *);
static void			 child_drop(struct child *);
static struct open_session	*open_session_find(uint32_t);
static unsigned int		 count_startups(void);
static int			 startups_should_drop(unsigned int);
static void			 accept_pause(void);
static void			 accept_resume(int, short, void *);
static unsigned int		 count_sessions(void);
static int			 same_peer(const struct sockaddr_storage *,
		    const struct sockaddr_storage *);
static unsigned int		 count_startups_from(
		    const struct sockaddr_storage *);
static void			 refuse_connection(int, int);
static void			 parent_accept(int, short, void *);
static void			 spawn_connection(int, int,
		    const struct sockaddr_storage *, socklen_t);
static void			 parent_handle_store_fork(struct open_session *,
		    uid_t, gid_t, const char *);
static void			 store_fork_failed(struct open_session *, int);
static int			 store_child_attach(struct store_child *,
		    struct open_session *);
static void			 store_child_session_gone(struct store_child *);
static void			 store_child_wire(struct store_child *);
static void			 store_child_parser(struct store_child *);
static void			 store_child_dispatch(int, short, void *);
static void			 store_child_timeout(int, short, void *);
static void			 store_child_teardown(struct store_child *,
		    int);
static void			 store_child_fail(struct store_child *);
static void			 bind_one(int, const struct sockaddr *,
		    socklen_t, uint16_t, int);
static void			 bind_listen_socket(const char *, uint16_t,
		    int);
static int			 send_chunked(struct imsgev *, uint32_t,
		    uint32_t, uint8_t *, size_t);
static uint8_t			*load_key_file(const char *, size_t *);
static int			 send_tls_cert(struct imsgev *);
static int			 send_keymgr_init(struct imsgev *,
		    struct aimap_config *);
static int			 keymgr_loaded(uint32_t, int);
static void			 keymgr_wait_loaded(void);
static void			 certs_pending_clear(void);
static int			 send_auth_init(struct imsgev *,
		    struct aimap_config *);
static void			 sighup_handler(int, short, void *);
static int			 shutdown_children_left(void);
static void			 sigterm_force(int, short, void *);
static __dead void		 shutdown_force(void);
static void			 sigterm_handler(int, short, void *);
static void			 sigchld_handler(int, short, void *);
static void			 reap_child(pid_t, int);
static int			 maildir_path_is_safe(const char *);
static int			 userbase_account(uint32_t, const char *,
		    uid_t *, gid_t *, char *);
static int			 userbase_read(const char *, const char *,
		    char **);
static int			 userbase_entry(char *, uid_t *, gid_t *,
		    char **);
static int			 userbase_maildir(const char *, const char *,
		    char *);

__dead void
parent_main(const char *conffile, int argc, char *argv[],
    struct aimap_config *conf, int debug)
{
	struct rlimit	 rl;
	int		 i;

	if (geteuid() != 0)
		fatalx("parent must start as root (running as uid %u)",
		    (unsigned int)geteuid());

	/* The daemon login class caps descriptors too low. */
	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		log_warn("getrlimit RLIMIT_NOFILE");
	else if (rl.rlim_cur < rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
			log_warn("setrlimit RLIMIT_NOFILE");
		else
			log_debug("raised RLIMIT_NOFILE soft limit to %llu",
			    (unsigned long long)rl.rlim_cur);
	}

	gconf = conf;
	conf_path = conffile;
	saved_argv = argv;
	/* Children are executed again by path. */
	if (argv[0][0] != '/')
		fatalx("%s: not an absolute path", argv[0]);
	if (realpath(argv[0], progpath) == NULL)
		fatal("realpath");

	tls_pair_check(conf);

	/* Binding below port 1024 needs root. */
	if (conf->port_cleartext != 0)
		bind_listen_socket(conf->listen_addr, conf->port_cleartext, 0);
	if (conf->port_implicit_tls != 0)
		bind_listen_socket(conf->listen_addr,
		    conf->port_implicit_tls, 1);
	if (n_listen == 0)
		fatalx("no usable \"listen on\" address in aimap.conf");

	if (!debug && daemon(1, 0) == -1)
		fatal("daemon");

	event_init();

	fork_child(PROC_KEYMGR, &iev_keymgr, parent_dispatch_child);
	if (send_keymgr_init(iev_keymgr, conf) == -1)
		fatalx("send_keymgr_init: could not initialize keymgr at boot");
	keymgr_wait_loaded();

	setup_done_send(iev_keymgr);

	signal_set(&ev_sighup, SIGHUP, sighup_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, sigterm_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, sigchld_handler, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);

	for (i = 0; i < n_listen; i++) {
		event_set(&listen_socks[i].ev, listen_socks[i].fd,
		    EV_READ | EV_PERSIST, parent_accept, &listen_socks[i]);
		event_add(&listen_socks[i].ev, NULL);
	}

	/*
	 * No setproctitle(), as rc.d matches the command line.  Every
	 * connection forks and passes descriptors, hence proc exec sendfd.
	 */
	if (pledge("stdio rpath inet proc exec sendfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
}

static __dead void
exec_self_as(const char *role)
{
	char	*nargv[16];
	int	 i, n;

	n = 0;
	nargv[n++] = progpath;
	nargv[n++] = "-x";
	/* Safe, since execv(3) never writes through argv. */
	nargv[n++] = (char *)role;
	for (i = 1; saved_argv[i] != NULL; i++) {
		if (strcmp(saved_argv[i], "-x") == 0) {
			/* A trailing -x would read past the NULL. */
			if (saved_argv[i + 1] == NULL)
				break;
			i++;
			continue;
		}
		if (n >= (int)nitems(nargv) - 1) {
			/* Truncating could split an option from its value. */
			log_warnx("%s: argv too long for the %s child",
			    __func__, role);
			_exit(1);
		}
		nargv[n++] = saved_argv[i];
	}
	nargv[n] = NULL;

	execv(nargv[0], nargv);
	_exit(1);
}

/*
 * For an essential child, where failure is fatal.
 */
static pid_t
fork_child(enum aimap_proc_type type, struct imsgev **ievp,
    void (*handler)(int, short, void *))
{
	pid_t	pid;

	if ((pid = fork_child_nonfatal(type, ievp, handler)) == -1)
		fatal("fork_child_nonfatal");
	return (pid);
}

static pid_t
fork_child_nonfatal(enum aimap_proc_type type, struct imsgev **ievp,
    void (*handler)(int, short, void *))
{
	struct rlimit	 rl;
	struct child	*c;
	pid_t		 pid;
	int		 sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1) {
		log_warn("socketpair");
		return (-1);
	}

	if ((pid = fork()) == -1) {
		log_warn("fork");
		close(sp[0]);
		close(sp[1]);
		return (-1);
	}

	if (pid == 0) {
		close(sp[0]);
		if (dup2(sp[1], 3) == -1)
			_exit(1);
		closefrom(4);

		/* Here, as setrlimit(2) needs a "proc" or "id" pledge. */
		if (type == PROC_PARSER) {
			rl.rlim_cur = PARSER_CPU_SOFT_SEC;
			rl.rlim_max = PARSER_CPU_HARD_SEC;
			if (setrlimit(RLIMIT_CPU, &rl) == -1)
				_exit(1);
		}

		exec_self_as(proc_name(type));
	}

	close(sp[1]);

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		log_warn("calloc");
		kill(pid, SIGKILL);
		close(sp[0]);
		return (-1);
	}
	c->pid = pid;
	c->type = type;
	imsgev_init(&c->iev, sp[0], handler, c);
	TAILQ_INSERT_TAIL(&children, c, entry);

	*ievp = &c->iev;
	return (pid);
}

/*
 * Send one socketpair end each to a and b.  Use id 0 for a child with one
 * peer.
 */
static int
setup_peer_send(struct imsgev *a, struct imsgev *b, int imsg_type,
    const char *imsgname, uint32_t id)
{
	int	sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1) {
		log_warn("setup_peer_send %s: socketpair", imsgname);
		return (-1);
	}

	if (imsg_compose(&a->ibuf, imsg_type, id, 0, sp[0], NULL, 0) == -1) {
		log_warn("setup_peer_send %s: imsg_compose (a)", imsgname);
		close(sp[0]);
		close(sp[1]);
		return (-1);
	}
	if (imsg_compose(&b->ibuf, imsg_type, id, 0, sp[1], NULL, 0) == -1) {
		log_warn("setup_peer_send %s: imsg_compose (b)", imsgname);
		close(sp[1]);
		return (-1);
	}

	if (imsgbuf_flush(&a->ibuf) == -1) {
		log_warn("setup_peer_send %s: imsgbuf_flush (a)", imsgname);
		return (-1);
	}
	if (imsgbuf_flush(&b->ibuf) == -1) {
		log_warn("setup_peer_send %s: imsgbuf_flush (b)", imsgname);
		return (-1);
	}
	return (0);
}

/*
 * Boot only, as it blocks until the child replies.
 */
static void
setup_done_send(struct imsgev *iev)
{
	struct imsg	 imsg;
	int		 n;

	if (imsg_compose(&iev->ibuf, IMSG_SETUP_DONE, 0, 0, -1, NULL, 0) == -1)
		fatal("imsg_compose IMSG_SETUP_DONE");
	if (imsgbuf_flush(&iev->ibuf) == -1)
		fatal("imsgbuf_flush");

	/* Get before reading, as the kernel may coalesce messages. */
	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n != 0)
			break;
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0)
			fatalx("%s: child closed channel", __func__);
	}

	if (imsg_get_type(&imsg) != IMSG_SETUP_DONE)
		fatalx("%s: expected IMSG_SETUP_DONE", __func__);
	imsg_free(&imsg);
}

/*
 * A broken channel ends that child, not aimap.
 */
static void
parent_dispatch_child(int fd, short event, void *arg)
{
	struct imsg_keymgr_loaded	 loaded;
	struct imsg_auth_cred		 req;
	struct child			*c = arg;
	struct imsgev			*iev = &c->iev;
	struct imsg			 imsg;
	struct open_session		*os;
	char				 maildir[STORE_MAILDIR_MAX];
	uid_t				 uid;
	gid_t				 gid;
	int				 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			log_debug("%s[%d]: channel closed: %s",
			    proc_name(c->type), c->pid, strerror(errno));
			child_drop(c);
			return;
		}
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1) {
			log_warn("%s[%d]: imsgbuf_read, killing it",
			    proc_name(c->type), c->pid);
			child_drop(c);
			return;
		}
		if (n == 0) {
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			log_warn("%s[%d]: imsgbuf_get, killing it",
			    proc_name(c->type), c->pid);
			child_drop(c);
			return;
		}
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_AUTH_CRED:
			if (imsg_get_data(&imsg, &req, sizeof(req)) == -1) {
				log_warnx("bad IMSG_AUTH_CRED");
				break;
			}
			/* The imsg data need not end in NUL. */
			req.username[sizeof(req.username) - 1] = '\0';

			if ((os = open_session_find(req.session_id)) == NULL) {
				log_warnx("IMSG_AUTH_CRED for unknown session "
				    "%u, refused", req.session_id);
				break;
			}
			/* Only this session's own auth worker may grant it. */
			if (iev != os->auth_iev) {
				log_warnx("IMSG_AUTH_CRED for session %u from "
				    "the wrong channel, refused",
				    req.session_id);
				break;
			}
			if (os->authenticated) {
				log_warnx("IMSG_AUTH_CRED for session %u: "
				    "already authenticated", req.session_id);
				/* Reply, as the listener has no timeout. */
				store_fork_failed(os, 0);
				break;
			}
			os->authenticated = 1;

			if (imsg_compose(&iev->ibuf, IMSG_AUTH_EXIT, 0, 0, -1,
			    NULL, 0) == -1)
				log_warn("session %u: imsg_compose "
				    "IMSG_AUTH_EXIT", req.session_id);

			if (userbase_account(req.session_id, req.username, &uid,
			    &gid, maildir) == -1) {
				store_fork_failed(os, 0);
				break;
			}
			parent_handle_store_fork(os, uid, gid, maildir);
			break;
		case IMSG_KEYMGR_LOADED:
			if (iev != iev_keymgr) {
				log_warnx("%s[%d]: IMSG_KEYMGR_LOADED refused",
				    proc_name(c->type), c->pid);
				break;
			}
			if (!recv_fixed(&imsg, &loaded, sizeof(loaded),
			    "IMSG_KEYMGR_LOADED"))
				break;
			if (keymgr_loaded(imsg_get_id(&imsg), loaded.ok) == 0)
				log_info("SIGHUP: TLS certificate and key "
				    "loaded");
			else
				log_warnx("SIGHUP: TLS certificate and key "
				    "refused, keeping the old");
			break;
		default:
			log_debug("%s: unhandled %d", __func__,
			    imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}
	imsgev_rearm_read(iev);
}

/*
 * The reaper frees c once SIGCHLD reports the exit.
 */
static void
child_drop(struct child *c)
{
	event_del(&c->iev.ev);
	kill(c->pid, SIGKILL);
}

static struct open_session *
open_session_find(uint32_t session_id)
{
	struct open_session	*os;

	TAILQ_FOREACH(os, &open_sessions, entry) {
		if (os->session_id == session_id)
			return (os);
	}
	return (NULL);
}

static unsigned int
count_startups(void)
{
	struct open_session	*os;
	unsigned int		 n = 0;

	TAILQ_FOREACH(os, &open_sessions, entry) {
		if (!os->authenticated)
			n++;
	}
	return (n);
}

/*
 * Drop rate% at begin, rising to all at full.
 */
static int
startups_should_drop(unsigned int nstartups)
{
	unsigned int	p;

	if (gconf->max_startups_full == 0)
		return (0);
	if (nstartups < gconf->max_startups_begin)
		return (0);
	if (nstartups >= gconf->max_startups_full)
		return (1);
	if (gconf->max_startups_rate >= 100)
		return (1);
	if (gconf->max_startups_full <= gconf->max_startups_begin)
		return (1);

	p = 100 - gconf->max_startups_rate;
	p *= nstartups - gconf->max_startups_begin;
	p /= gconf->max_startups_full - gconf->max_startups_begin;
	p += gconf->max_startups_rate;
	return (arc4random_uniform(100) < p);
}

static void
accept_pause(void)
{
	struct timeval	 tv = { ACCEPT_PAUSE_SEC, 0 };
	int		 i;

	for (i = 0; i < n_listen; i++)
		event_del(&listen_socks[i].ev);
	evtimer_set(&ev_accept_pause, accept_resume, NULL);
	evtimer_add(&ev_accept_pause, &tv);
}

static void
accept_resume(int fd, short event, void *arg)
{
	int	 i;

	if (shutting_down)
		return;
	for (i = 0; i < n_listen; i++)
		event_add(&listen_socks[i].ev, NULL);
}

static unsigned int
count_sessions(void)
{
	struct open_session	*os;
	unsigned int		 n = 0;

	TAILQ_FOREACH(os, &open_sessions, entry)
		n++;
	return (n);
}

static int
same_peer(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return (0);
	if (a->ss_family == AF_INET)
		return (memcmp(&((const struct sockaddr_in *)a)->sin_addr,
		    &((const struct sockaddr_in *)b)->sin_addr,
		    sizeof(struct in_addr)) == 0);
	if (a->ss_family == AF_INET6)
		return (memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
		    &((const struct sockaddr_in6 *)b)->sin6_addr,
		    sizeof(struct in6_addr)) == 0);
	return (0);
}

/*
 * Count unauthenticated sessions from this peer's address.
 */
static unsigned int
count_startups_from(const struct sockaddr_storage *ss)
{
	struct open_session	*os;
	unsigned int		 n = 0;

	TAILQ_FOREACH(os, &open_sessions, entry) {
		if (!os->authenticated && same_peer(&os->peer, ss))
			n++;
	}
	return (n);
}

/*
 * Only cleartext connections can read a plain BYE.
 */
static void
refuse_connection(int fd, int cleartext)
{
	static const char	 bye[] = "* BYE [UNAVAILABLE] too many "
				    "connections, try again later\r\n";

	if (cleartext)
		(void)write(fd, bye, sizeof(bye) - 1);
	close(fd);
}

static void
parent_accept(int fd, short event, void *arg)
{
	struct listen_sock	*ls = arg;
	struct sockaddr_storage	 ss;
	socklen_t		 sslen = sizeof(ss);
	int			 client_fd, flags, on = 1;
	unsigned int		 nstartups, nopen, nsource;

	if ((client_fd = accept(fd, (struct sockaddr *)&ss, &sslen)) == -1) {
		/* Otherwise the listen event fires again at once. */
		if (errno == EMFILE || errno == ENFILE) {
			log_warn("accept, pausing %ds", ACCEPT_PAUSE_SEC);
			accept_pause();
		} else
			log_warn("accept");
		return;
	}

	nopen = count_sessions();
	if (nopen >= gconf->connections_max) {
		if (!connections_full)
			log_warnx("connections max reached (%u open), "
			    "refusing new connections", nopen);
		connections_full = 1;
		refuse_connection(client_fd, !ls->implicit_tls);
		return;
	}
	if (connections_full) {
		log_info("below connections max again (%u open), "
		    "accepting", nopen);
		connections_full = 0;
	}

	if (gconf->max_startups_per_source != 0) {
		nsource = count_startups_from(&ss);
		if (nsource >= gconf->max_startups_per_source) {
			log_debug("startups per-source: refusing connection "
			    "(%u unauthenticated from its address)", nsource);
			refuse_connection(client_fd, !ls->implicit_tls);
			return;
		}
	}

	nstartups = count_startups();
	if (startups_should_drop(nstartups)) {
		log_debug("MaxStartups: refusing connection (%u "
		    "unauthenticated already open)", nstartups);
		refuse_connection(client_fd, !ls->implicit_tls);
		return;
	}

	/* The listening socket is blocking, so set O_NONBLOCK here. */
	if ((flags = fcntl(client_fd, F_GETFL)) == -1 ||
	    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_warn("fcntl O_NONBLOCK");
		close(client_fd);
		return;
	}

	/* So a session whose client vanished ends. */
	if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &on,
	    sizeof(on)) == -1)
		log_warn("setsockopt SO_KEEPALIVE");

	spawn_connection(client_fd, ls->implicit_tls, &ss, sslen);
}

static void
spawn_connection(int client_fd, int implicit_tls,
    const struct sockaddr_storage *ss, socklen_t sslen)
{
	struct imsg_listener_session_init	 init;
	struct open_session			*os, *it;
	struct imsgev				*new_listener_iev;
	struct imsgev				*new_auth_iev;
	unsigned int				 nopen = 0;
	uint32_t				 session_id;
	pid_t					 listener_pid, auth_pid;

	session_id = next_session_id++;
	/* Id 0 means the auth peer to the listener. */
	if (next_session_id == 0)
		next_session_id = 1;

	TAILQ_FOREACH(it, &open_sessions, entry)
		nopen++;
	if (nopen >= OPEN_SESSION_MAX) {
		log_warnx("refusing connection: %u sessions open "
		    "(OPEN_SESSION_MAX)", nopen);
		close(client_fd);
		return;
	}

	if ((os = calloc(1, sizeof(*os))) == NULL) {
		log_warn("calloc open_session (session %u)", session_id);
		close(client_fd);
		return;
	}
	os->session_id = session_id;
	os->peer = *ss;

	if ((listener_pid = fork_child_nonfatal(PROC_LISTENER,
	    &new_listener_iev, parent_dispatch_child)) == -1) {
		log_warnx("session %u: refusing connection: no listener-worker",
		    session_id);
		free(os);
		close(client_fd);
		return;
	}
	os->listener_pid = listener_pid;
	os->listener_iev = new_listener_iev;
	/* Inserted early, so the reaper always finds it. */
	TAILQ_INSERT_TAIL(&open_sessions, os, entry);

	if ((auth_pid = fork_child_nonfatal(PROC_AUTH, &new_auth_iev,
	    parent_dispatch_child)) == -1) {
		log_warnx("session %u: no auth-worker for this connection",
		    session_id);
	} else {
		os->auth_pid = auth_pid;
		os->auth_iev = new_auth_iev;
		if (send_auth_init(new_auth_iev, gconf) == -1 ||
		    setup_peer_send(new_listener_iev, new_auth_iev,
		    IMSG_SETUP_PEER, "IMSG_SETUP_PEER", 0) == -1)
			goto fail_close;
	}

	if (setup_peer_send(new_listener_iev, iev_keymgr, IMSG_SETUP_PEER,
	    "IMSG_SETUP_PEER", session_id) == -1)
		goto fail_close;

	memset(&init, 0, sizeof(init));
	init.session_id = session_id;
	init.implicit_tls = implicit_tls;
	init.remote_ss = *ss;
	init.remote_sslen = sslen;
	init.idle_poll_secs = gconf->idle_poll_secs;
	init.login_grace_secs = gconf->login_grace_secs;
	init.append_max = gconf->append_max;
	if (imsg_compose(&new_listener_iev->ibuf, IMSG_LISTENER_SESSION_INIT,
	    0, 0, client_fd, &init, sizeof(init)) == -1) {
		log_warnx("session %u: imsg_compose "
		    "IMSG_LISTENER_SESSION_INIT, connection lost", session_id);
		close(client_fd);
		goto fail_workers;
	}
	/* The imsg owns client_fd now. */
	if (send_tls_cert(new_listener_iev) == -1)
		goto fail_workers;
	return;

fail_close:
	close(client_fd);	/* Not yet given to imsg. */
fail_workers:
	/* The reaper frees os, not this path. */
	log_warnx("session %u: refusing connection: worker wiring failed",
	    session_id);
	kill(os->listener_pid, SIGKILL);
	if (os->auth_pid != 0)
		kill(os->auth_pid, SIGKILL);
}

/*
 * Empty, absolute or ".." paths could escape the spool.
 */
static int
maildir_path_is_safe(const char *p)
{
	const char	*seg = p, *slash;
	size_t		len;

	if (p == NULL || p[0] == '\0' || p[0] == '/')
		return (0);
	for (;;) {
		slash = strchr(seg, '/');
		len = slash ? (size_t)(slash - seg) : strlen(seg);
		if (len == 1 && seg[0] == '.')
			return (0);
		if (len == 2 && seg[0] == '.' && seg[1] == '.')
			return (0);
		if (slash == NULL)
			break;
		seg = slash + 1;
	}
	return (1);
}

/*
 * The auth worker vouches for the password.  The userbase names the
 * account.
 */
static int
userbase_account(uint32_t session_id, const char *username, uid_t *uid,
    gid_t *gid, char *maildir)
{
	char	*val, *home;
	int	 ret = -1;

	if (userbase_read(gconf->userbase_file, username, &val) == -1)
		return (-1);
	if (val == NULL)
		log_warnx("session %u: \"%s\": no userbase entry", session_id,
		    username);
	else if (userbase_entry(val, uid, gid, &home) == -1)
		log_warnx("session %u: \"%s\": invalid userbase entry",
		    session_id, username);
	else if (userbase_maildir(home, gconf->spool_root, maildir) == -1)
		log_warnx("session %u: \"%s\": home %s not a maildir in spool",
		    session_id, username, home);
	else
		ret = 0;
	free(val);
	return (ret);
}

/*
 * Match table(5) keys as smtpd(8) does.  Case is ignored, and the last line
 * wins.
 */
static int
userbase_read(const char *path, const char *username, char **valp)
{
	struct stat	 st;
	size_t		 linesize = 0;
	FILE		*fp;
	char		*line = NULL, *key, *val;
	int		 fd, lineno = 0, ret = 0;

	*valp = NULL;
	if ((fd = open(path, O_RDONLY)) == -1) {
		log_warn("%s", path);
		return (-1);
	}
	if (fstat(fd, &st) == -1) {
		log_warn("%s", path);
		close(fd);
		return (-1);
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH))) {
		log_warnx("%s: not a regular file writable only by root", path);
		close(fd);
		return (-1);
	}
	if ((fp = fdopen(fd, "r")) == NULL) {
		log_warn("%s", path);
		close(fd);
		return (-1);
	}

	while (getline(&line, &linesize, fp) != -1) {
		lineno++;
		if (table_line(line, &key, &val) == -1) {
			log_warnx("%s:%d invalid map entry", path, lineno);
			ret = -1;
			break;
		}
		if (key == NULL || strcasecmp(key, username) != 0)
			continue;
		free(*valp);
		if ((*valp = strdup(val)) == NULL) {
			log_warn("strdup");
			ret = -1;
			break;
		}
	}
	if (ret == 0 && ferror(fp)) {
		log_warn("getline %s", path);
		ret = -1;
	}
	if (ret == -1) {
		free(*valp);
		*valp = NULL;
	}
	free(line);
	fclose(fp);
	return (ret);
}

/*
 * Parse uid:gid:home as smtpd(8) does.  The home may hold colons.
 */
static int
userbase_entry(char *val, uid_t *uid, gid_t *gid, char **home)
{
	const char	*errstr;
	char		*gidp;

	if ((gidp = strchr(val, ':')) == NULL)
		return (-1);
	*gidp++ = '\0';
	if ((*home = strchr(gidp, ':')) == NULL)
		return (-1);
	*(*home)++ = '\0';
	if (!isdigit((unsigned char)val[0]) ||
	    !isdigit((unsigned char)gidp[0]))
		return (-1);
	*uid = strtonum(val, 0, UINT_MAX, &errstr);
	if (errstr != NULL)
		return (-1);
	*gid = strtonum(gidp, 0, UINT_MAX, &errstr);
	if (errstr != NULL)
		return (-1);
	return (0);
}

/*
 * The store's root is the spool, so strip it.
 */
static int
userbase_maildir(const char *home, const char *spool, char *maildir)
{
	size_t	 len;

	len = strlen(spool);
	while (len > 0 && spool[len - 1] == '/')
		len--;
	if (strncmp(home, spool, len) != 0 || home[len] != '/')
		return (-1);
	if (strlcpy(maildir, home + len + 1, STORE_MAILDIR_MAX) >=
	    STORE_MAILDIR_MAX)
		return (-1);
	return (maildir_path_is_safe(maildir) ? 0 : -1);
}

static void
parent_handle_store_fork(struct open_session *os, uid_t uid, gid_t gid,
    const char *maildir)
{
	struct store_child	*sc;
	int			 pair[2];
	pid_t			 pid;
	struct timeval		 tv;
	struct imsg_store_init	 init_payload;
	struct store_child	*it;
	uint32_t		 session_id = os->session_id;

	if (os->listener_iev == NULL) {
		log_warnx("refusing store spawn for session %u: "
		    "listener-worker is gone", session_id);
		return;
	}

	if (uid == 0 || gid == 0 ||
	    uid == (uid_t)-1 || gid == (gid_t)-1) {
		log_warnx("refusing store spawn: privileged uid=%u gid=%u "
		    "for session %u", (unsigned int)uid, (unsigned int)gid,
		    session_id);
		goto fail;
	}
	if (!maildir_path_is_safe(maildir)) {
		log_warnx("refusing store spawn: unsafe maildir for "
		    "session %u", session_id);
		goto fail;
	}

	/* A second store would orphan the first. */
	if (os->store != NULL) {
		log_warnx("refusing store spawn: session %u already "
		    "has a store child", session_id);
		goto fail;
	}

	TAILQ_FOREACH(it, &store_children, entry) {
		if (!it->exiting && it->uid == uid && it->gid == gid &&
		    strcmp(it->maildir, maildir) == 0) {
			if (it->nsessions >= gconf->account_sessions) {
				log_info("session %u: refusing login: uid %u "
				    "has %u sessions (account sessions)",
				    session_id, (unsigned int)uid,
				    it->nsessions);
				store_fork_failed(os, 1);
				return;
			}
			if (store_child_attach(it, os) == -1)
				goto fail;
			log_debug("session %u: joined the store child of "
			    "session %u", session_id, it->session_id);
			return;
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) == -1) {
		log_warn("socketpair");
		goto fail;
	}

	if ((pid = fork()) == -1) {
		log_warn("fork");
		close(pair[0]);
		close(pair[1]);
		goto fail;
	}

	if (pid == 0) {
		close(pair[0]);
		if (dup2(pair[1], 3) == -1)
			_exit(1);
		closefrom(4);

		exec_self_as("store");
	}

	close(pair[1]);

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL) {
		log_warn("calloc store child (session %u)", session_id);
		kill(pid, SIGKILL);
		close(pair[0]);
		goto fail;
	}
	sc->session_id = session_id;
	sc->uid = uid;
	sc->gid = gid;
	(void)strlcpy(sc->maildir, maildir, sizeof(sc->maildir));
	sc->pid = pid;
	sc->pending = 1;
	imsgev_init(&sc->iev, pair[0], store_child_dispatch, sc);

	/* Zeroed, so no stack bytes reach the store child. */
	memset(&init_payload, 0, sizeof(init_payload));
	init_payload.uid = uid;
	init_payload.gid = gid;
	strlcpy(init_payload.spool_root, gconf->spool_root,
	    sizeof(init_payload.spool_root));
	strlcpy(init_payload.maildir, maildir, sizeof(init_payload.maildir));
	init_payload.bodystructure_read_max = gconf->bodystructure_read_max;
	init_payload.append_max = gconf->append_max;
	init_payload.lock_timeout_secs = gconf->lock_timeout_secs;
	if (imsg_compose(&sc->iev.ibuf, IMSG_STORE_INIT, 0, 0, -1,
	    &init_payload, sizeof(init_payload)) == -1) {
		log_warn("imsg_compose IMSG_STORE_INIT");
		goto fail_kill;
	}

	if (imsg_compose(&sc->iev.ibuf, IMSG_SETUP_DONE, 0, 0, -1, NULL, 0)
	    == -1) {
		log_warn("imsg_compose IMSG_SETUP_DONE");
		goto fail_kill;
	}

	if (store_child_attach(sc, os) == -1)
		goto fail_kill;

	evtimer_set(&sc->timeout_ev, store_child_timeout, sc);
	tv.tv_sec = STORE_SETUP_TIMEOUT_SEC;
	tv.tv_usec = 0;
	evtimer_add(&sc->timeout_ev, &tv);

	TAILQ_INSERT_TAIL(&store_children, sc, entry);
	log_info("session %u: store child %d for uid %u", session_id, (int)pid,
	    (unsigned int)uid);
	return;

fail_kill:
	kill(pid, SIGKILL);
	event_del(&sc->iev.ev);
	close(sc->iev.ibuf.fd);
	/* Closing alone would leak what imsgbuf_init() allocated. */
	imsgbuf_clear(&sc->iev.ibuf);
	free(sc);
fail:
	store_fork_failed(os, 0);
}

static void
store_fork_failed(struct open_session *os, int limit)
{
	struct imsg_store_fork	 fail_payload;

	if (os->listener_iev == NULL)
		return;
	memset(&fail_payload, 0, sizeof(fail_payload));
	fail_payload.session_id = os->session_id;
	fail_payload.limit = limit;
	if (imsg_compose(&os->listener_iev->ibuf, IMSG_STORE_FORK, 0, 0, -1,
	    &fail_payload, sizeof(fail_payload)) == -1)
		log_warn("imsg_compose IMSG_STORE_FORK (failure reply)");
}

static int
store_child_attach(struct store_child *sc, struct open_session *os)
{
	if (!sc->pending && setup_peer_send(&sc->iev, os->listener_iev,
	    IMSG_SETUP_PEER, "IMSG_SETUP_PEER", os->session_id) == -1)
		return (-1);
	os->store = sc;
	sc->nsessions++;
	return (0);
}

/*
 * Answer OK only once the login's store is ready.
 */
static void
store_child_wire(struct store_child *sc)
{
	struct open_session	*os;

	TAILQ_FOREACH(os, &open_sessions, entry) {
		if (os->store != sc || os->listener_iev == NULL)
			continue;
		if (setup_peer_send(&sc->iev, os->listener_iev,
		    IMSG_SETUP_PEER, "IMSG_SETUP_PEER", os->session_id) == 0)
			continue;
		os->store = NULL;
		store_child_session_gone(sc);
		store_fork_failed(os, 0);
	}
}

/*
 * The parent decides when the store is done.
 */
static void
store_child_session_gone(struct store_child *sc)
{
	if (sc->nsessions > 0)
		sc->nsessions--;
	if (sc->nsessions > 0 || sc->exiting)
		return;
	sc->exiting = 1;
	if (imsg_compose(&sc->iev.ibuf, IMSG_STORE_EXIT, 0, 0, -1, NULL,
	    0) == -1) {
		log_warn("session %u: imsg_compose IMSG_STORE_EXIT",
		    sc->session_id);
		store_child_fail(sc);
	}
}

/*
 * The store's pledge lacks proc and exec.
 */
static void
store_child_parser(struct store_child *sc)
{
	struct imsg_parser_init	 payload;
	struct imsgev		*parser_iev;
	pid_t			 pid;

	if (sc->parser_pid != 0) {
		kill(sc->parser_pid, SIGKILL);
		sc->parser_pid = 0;
	}
	if ((pid = fork_child_nonfatal(PROC_PARSER, &parser_iev,
	    parent_dispatch_child)) == -1) {
		log_warnx("session %u: could not spawn a parser-worker",
		    sc->session_id);
		goto none;
	}
	memset(&payload, 0, sizeof(payload));
	payload.uid = sc->uid;
	payload.gid = sc->gid;
	payload.bodystructure_read_max = gconf->bodystructure_read_max;
	if (imsg_compose(&parser_iev->ibuf, IMSG_PARSER_INIT, 0, 0, -1,
	    &payload, sizeof(payload)) == -1) {
		log_warn("imsg_compose IMSG_PARSER_INIT");
		goto kill;
	}
	if (imsgbuf_flush(&parser_iev->ibuf) == -1) {
		log_warn("imsgbuf_flush IMSG_PARSER_INIT");
		goto kill;
	}
	/* Session ids skip 0, so it names no session. */
	if (setup_peer_send(&sc->iev, parser_iev, IMSG_SETUP_PEER,
	    "IMSG_SETUP_PEER", 0) == -1)
		goto kill;
	sc->parser_pid = pid;
	return;

kill:
	kill(pid, SIGKILL);
none:
	if (imsg_compose(&sc->iev.ibuf, IMSG_PARSER_NONE, 0, 0, -1, NULL,
	    0) == -1)
		log_warn("session %u: imsg_compose IMSG_PARSER_NONE",
		    sc->session_id);
}

static void
store_child_dispatch(int fd, short event, void *arg)
{
	struct store_child	*sc = arg;
	struct imsg		 imsg;
	int			 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&sc->iev.ibuf) == -1) {
			store_child_fail(sc);
			return;
		}
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&sc->iev.ibuf)) == -1 || n == 0) {
			store_child_fail(sc);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&sc->iev.ibuf, &imsg)) == -1) {
			store_child_fail(sc);
			return;
		}
		if (n == 0)
			break;

		if (sc->pending && imsg_get_type(&imsg) == IMSG_SETUP_DONE) {
			evtimer_del(&sc->timeout_ev);
			sc->pending = 0;
			imsg_free(&imsg);
			store_child_wire(sc);
			continue;
		}
		if (imsg_get_type(&imsg) == IMSG_PARSER_WANT) {
			imsg_free(&imsg);
			store_child_parser(sc);
			continue;
		}

		log_debug("%s: unhandled %d (session %u)", __func__,
		    imsg_get_type(&imsg), sc->session_id);
		imsg_free(&imsg);
	}
	imsgev_rearm_read(&sc->iev);
}

static void
store_child_timeout(int fd, short event, void *arg)
{
	struct store_child	*sc = arg;

	log_warnx("session %u: store setup timed out after %ds",
	    sc->session_id, STORE_SETUP_TIMEOUT_SEC);
	store_child_fail(sc);
}

static void
store_child_teardown(struct store_child *sc, int already_dead)
{
	struct open_session	*os;

	TAILQ_FOREACH(os, &open_sessions, entry) {
		if (os->store != sc)
			continue;
		os->store = NULL;
		if (sc->pending)
			store_fork_failed(os, 0);
	}
	evtimer_del(&sc->timeout_ev);
	if (!already_dead)
		kill(sc->pid, SIGKILL);
	event_del(&sc->iev.ev);
	close(sc->iev.ibuf.fd);
	/* Closing alone would leak what imsgbuf_init() allocated. */
	imsgbuf_clear(&sc->iev.ibuf);
	TAILQ_REMOVE(&store_children, sc, entry);
	free(sc);
}

static void
store_child_fail(struct store_child *sc)
{
	store_child_teardown(sc, 0);
}

static void
bind_one(int family, const struct sockaddr *sa, socklen_t salen,
    uint16_t port, int implicit_tls)
{
	struct listen_sock	*ls;
	int			 fd, val;

	if ((fd = socket(family, SOCK_STREAM, 0)) == -1)
		fatal("socket");

	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1)
		fatal("setsockopt");

	if (bind(fd, sa, salen) == -1)
		fatal("bind port %u", port);
	if (listen(fd, 16) == -1)
		fatal("listen");

	ls = &listen_socks[n_listen++];
	ls->fd = fd;
	ls->implicit_tls = implicit_tls;
}

/*
 * Take "*" or a literal address, without DNS.
 */
static void
bind_listen_socket(const char *addr, uint16_t port, int implicit_tls)
{
	struct sockaddr_in6	 sin6;
	struct sockaddr_in	 sin;
	struct in6_addr		 ina6;
	struct in_addr		 ina;

	if (strcmp(addr, "*") == 0) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(port);
		bind_one(AF_INET, (struct sockaddr *)&sin, sizeof(sin), port,
		    implicit_tls);

		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = in6addr_any;
		sin6.sin6_port = htons(port);
		bind_one(AF_INET6, (struct sockaddr *)&sin6, sizeof(sin6), port,
		    implicit_tls);
		return;
	}

	memset(&ina, 0, sizeof(ina));
	if (inet_pton(AF_INET, addr, &ina) == 1) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = ina;
		sin.sin_port = htons(port);
		bind_one(AF_INET, (struct sockaddr *)&sin, sizeof(sin), port,
		    implicit_tls);
		return;
	}

	memset(&ina6, 0, sizeof(ina6));
	if (inet_pton(AF_INET6, addr, &ina6) == 1) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ina6;
		sin6.sin6_port = htons(port);
		bind_one(AF_INET6, (struct sockaddr *)&sin6, sizeof(sin6), port,
		    implicit_tls);
		return;
	}

	fatalx("%s: \"%s\" is not \"*\" or a literal IPv4/IPv6 address",
	    __func__, addr);
}

/*
 * Keep each piece under the imsgbuf's default maximum.
 */
static int
send_chunked(struct imsgev *iev, uint32_t type, uint32_t id, uint8_t *data,
    size_t len)
{
	struct imsg_tls_chunk	 c;
	struct iovec		 iov[2];
	size_t			 n;

	memset(&c, 0, sizeof(c));
	c.len = len;
	do {
		n = len - c.offset;
		if (n > MAX_IMSG_DATA_SIZE - sizeof(c))
			n = MAX_IMSG_DATA_SIZE - sizeof(c);
		iov[0].iov_base = &c;
		iov[0].iov_len = sizeof(c);
		iov[1].iov_base = n > 0 ? data + c.offset : NULL;
		iov[1].iov_len = n;
		if (imsg_composev(&iev->ibuf, type, id, 0, -1, iov,
		    n > 0 ? 2 : 1) == -1)
			return (-1);
		c.offset += n;
	} while (c.offset < len);
	return (0);
}

static int
send_tls_cert(struct imsgev *iev)
{
	if (send_chunked(iev, IMSG_TLS_CERT, 0, live_cert,
	    live_cert_len) == -1) {
		log_warn("imsg_compose IMSG_TLS_CERT");
		return (-1);
	}
	if (imsgbuf_flush(&iev->ibuf) == -1) {
		log_warn("imsgbuf_flush IMSG_TLS_CERT");
		return (-1);
	}
	return (0);
}

/*
 * Check the descriptor that is read, not the path.
 */
static uint8_t *
load_key_file(const char *path, size_t *lenp)
{
	struct stat	 st;
	uint8_t		*buf = NULL;
	ssize_t		 n;
	int		 fd;

	*lenp = 0;
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
		log_warn("%s", path);
		return (NULL);
	}
	if (fstat(fd, &st) == -1)
		log_warn("fstat %s", path);
	else if (st.st_uid != 0)
		log_warnx("%s: not owned by uid 0", path);
	else if (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO) & ~0740)
		log_warnx("%s: insecure permissions", path);
	else if ((buf = malloc(st.st_size)) == NULL)
		log_warn("%s", path);
	else if ((n = read(fd, buf, st.st_size)) != st.st_size) {
		if (n == -1)
			log_warn("read %s", path);
		else
			log_warnx("%s: short read", path);
		freezero(buf, st.st_size);
		buf = NULL;
	} else
		*lenp = st.st_size;
	close(fd);
	return (buf);
}

/*
 * Both halves carry one id, which keymgr's answer repeats.
 */
static int
send_keymgr_init(struct imsgev *iev, struct aimap_config *conf)
{
	struct cert_pending	*cp;
	uint8_t			*cert, *key;
	size_t			 cert_len = 0, key_len;
	int			 rc;

	if ((cp = calloc(1, sizeof(*cp))) == NULL) {
		log_warn("calloc");
		return (-1);
	}
	if ((cert = tls_load_file(conf->tls_cert_file, &cert_len, NULL))
	    == NULL) {
		log_warn("%s", conf->tls_cert_file);
		cert_len = 0;
	}
	key = load_key_file(conf->tls_key_file, &key_len);

	cp->gen = ++keymgr_gen;
	rc = send_chunked(iev, IMSG_TLS_CERT, cp->gen, cert, cert_len);
	if (rc == 0)
		rc = send_chunked(iev, IMSG_KEYMGR_INIT, cp->gen, key,
		    key_len);
	freezero(key, key_len);
	if (rc == -1)
		log_warn("imsg_compose IMSG_KEYMGR_INIT");
	else if ((rc = imsgbuf_flush(&iev->ibuf)) == -1)
		log_warn("imsgbuf_flush IMSG_KEYMGR_INIT");
	if (rc == -1) {
		tls_unload_file(cert, cert_len);
		free(cp);
		return (-1);
	}

	cp->cert = cert;
	cp->len = cert_len;
	TAILQ_INSERT_TAIL(&certs_pending, cp, entry);
	return (0);
}

/*
 * Answers come in order, so older pairs got none.
 */
static int
keymgr_loaded(uint32_t gen, int ok)
{
	struct cert_pending	*cp;

	while ((cp = TAILQ_FIRST(&certs_pending)) != NULL && cp->gen < gen) {
		TAILQ_REMOVE(&certs_pending, cp, entry);
		tls_unload_file(cp->cert, cp->len);
		free(cp);
	}
	if (cp == NULL || cp->gen != gen) {
		log_warnx("keymgr: answer for unknown pair %u", gen);
		return (-1);
	}
	TAILQ_REMOVE(&certs_pending, cp, entry);

	if (ok) {
		tls_unload_file(live_cert, live_cert_len);
		live_cert = cp->cert;
		live_cert_len = cp->len;
	} else
		tls_unload_file(cp->cert, cp->len);
	free(cp);
	return (ok ? 0 : -1);
}

static void
keymgr_wait_loaded(void)
{
	struct imsg_keymgr_loaded	 loaded;
	struct imsg			 imsg;
	int				 n;

	for (;;) {
		if ((n = imsgbuf_get(&iev_keymgr->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n != 0)
			break;
		if ((n = imsgbuf_read(&iev_keymgr->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0)
			fatalx("keymgr: exited before loading the TLS key");
	}
	if (imsg_get_type(&imsg) != IMSG_KEYMGR_LOADED ||
	    !recv_fixed(&imsg, &loaded, sizeof(loaded), "IMSG_KEYMGR_LOADED"))
		fatalx("%s: expected IMSG_KEYMGR_LOADED", __func__);
	if (keymgr_loaded(imsg_get_id(&imsg), loaded.ok) == -1)
		fatalx("keymgr: TLS certificate and key not loaded");
	imsg_free(&imsg);
}

static void
certs_pending_clear(void)
{
	struct cert_pending	*cp;

	while ((cp = TAILQ_FIRST(&certs_pending)) != NULL) {
		TAILQ_REMOVE(&certs_pending, cp, entry);
		tls_unload_file(cp->cert, cp->len);
		free(cp);
	}
}

/*
 * Check the pair before daemonizing, so that rc.d sees a bad one.
 * Keymgr checks it again when it loads it.
 */
void
tls_pair_check(struct aimap_config *conf)
{
	EVP_PKEY	*pkey;
	uint8_t		*cert, *key;
	size_t		 cert_len, key_len;
	X509		*x509;
	BIO		*bio;

	if ((cert = tls_load_file(conf->tls_cert_file, &cert_len, NULL))
	    == NULL)
		fatal("%s", conf->tls_cert_file);
	if ((key = load_key_file(conf->tls_key_file, &key_len)) == NULL)
		fatalx("%s: not loaded", conf->tls_key_file);

	if ((bio = BIO_new_mem_buf(cert, (int)cert_len)) == NULL ||
	    (x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL)
		fatalx("%s: no PEM certificate", conf->tls_cert_file);
	BIO_free(bio);
	if ((bio = BIO_new_mem_buf(key, (int)key_len)) == NULL ||
	    (pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL)
		fatalx("%s: no PEM private key", conf->tls_key_file);
	BIO_free(bio);
	freezero(key, key_len);

	if (X509_check_private_key(x509, pkey) != 1)
		fatalx("%s: does not match %s", conf->tls_cert_file,
		    conf->tls_key_file);
	EVP_PKEY_free(pkey);
	X509_free(x509);
	tls_unload_file(cert, cert_len);
}

static int
send_auth_init(struct imsgev *iev, struct aimap_config *conf)
{
	struct imsg_auth_init	 init;

	memset(&init, 0, sizeof(init));
	strlcpy(init.cred_file, conf->cred_file, sizeof(init.cred_file));

	if (imsg_compose(&iev->ibuf, IMSG_AUTH_INIT, 0, 0, -1,
	    &init, sizeof(init)) == -1) {
		log_warn("imsg_compose IMSG_AUTH_INIT");
		return (-1);
	}
	if (imsgbuf_flush(&iev->ibuf) == -1) {
		log_warn("imsgbuf_flush IMSG_AUTH_INIT");
		return (-1);
	}
	return (0);
}

/*
 * Changing listen_addr, port or cred_file needs a restart.
 */
static void
sighup_handler(int fd, short event, void *arg)
{
	struct aimap_config	 newconf;

	log_info("SIGHUP: reloading %s", conf_path);

	memset(&newconf, 0, sizeof(newconf));
	if (parse_config(conf_path, &newconf) == -1) {
		log_warnx("SIGHUP: %s: reload failed, keeping the "
		    "already-running configuration", conf_path);
		return;
	}

	if (strcmp(newconf.listen_addr, gconf->listen_addr) != 0 ||
	    newconf.port_cleartext != gconf->port_cleartext ||
	    newconf.port_implicit_tls != gconf->port_implicit_tls) {
		log_warnx("SIGHUP: %s: \"listen on\" changed, takes effect on "
		    "restart", conf_path);
	}
	if (strcmp(newconf.cred_file, gconf->cred_file) != 0) {
		log_warnx("SIGHUP: %s: \"credentials\" changed, takes effect "
		    "on restart", conf_path);
	}

	strlcpy(newconf.listen_addr, gconf->listen_addr,
	    sizeof(newconf.listen_addr));
	newconf.port_cleartext = gconf->port_cleartext;
	newconf.port_implicit_tls = gconf->port_implicit_tls;
	strlcpy(newconf.cred_file, gconf->cred_file, sizeof(newconf.cred_file));
	*gconf = newconf;

	/* Keymgr holds every connection's key, so push it. */
	if (iev_keymgr != NULL) {
		if (send_keymgr_init(iev_keymgr, gconf) == -1)
			log_warnx("SIGHUP: TLS certificate and key not sent "
			    "to keymgr");
	} else
		log_warnx("SIGHUP: keymgr is gone, TLS private key not "
		    "reloaded");

	log_info("SIGHUP: reload complete");
}

static int
shutdown_children_left(void)
{
	struct store_child	*sc;
	struct child		*c;
	int			 n = 0;

	TAILQ_FOREACH(c, &children, entry)
		n++;
	TAILQ_FOREACH(sc, &store_children, entry)
		n++;
	return (n);
}

static void
sigterm_force(int fd, short event, void *arg)
{
	shutdown_force();
}

/*
 * SIGKILL any child that stayed, then exit.
 */
static __dead void
shutdown_force(void)
{
	struct store_child	*sc;
	struct child		*c;
	int			 n = 0;

	TAILQ_FOREACH(c, &children, entry) {
		kill(c->pid, SIGKILL);
		n++;
	}
	TAILQ_FOREACH(sc, &store_children, entry) {
		kill(sc->pid, SIGKILL);
		n++;
	}
	if (n > 0)
		log_warnx("shutdown: killed %d child(ren) that stayed", n);
	log_info("shutdown complete");
	exit(0);
}

/*
 * Workers get EOF, not a signal, and end themselves.
 */
static void
sigterm_handler(int fd, short event, void *arg)
{
	struct timeval	 tv;
	struct child	*c;
	int		 i;

	if (shutting_down) {
		log_info("SIGTERM again: not waiting for children");
		shutdown_force();
	}
	shutting_down = 1;
	log_info("SIGTERM: shutting down");

	for (i = 0; i < n_listen; i++)
		event_del(&listen_socks[i].ev);

	TAILQ_FOREACH(c, &children, entry) {
		if (c->type != PROC_LISTENER)
			continue;
		event_del(&c->iev.ev);
		/* The reaper must not close this again. */
		if (c->iev.ibuf.fd != -1) {
			close(c->iev.ibuf.fd);
			c->iev.ibuf.fd = -1;
		}
	}

	/* Ask keymgr, so a bare EOF means a crash. */
	if (iev_keymgr != NULL &&
	    (imsg_compose(&iev_keymgr->ibuf, IMSG_KEYMGR_SHUTDOWN, 0, 0,
	    -1, NULL, 0) == -1 || imsgbuf_flush(&iev_keymgr->ibuf) == -1))
		log_warn("shutdown: could not tell keymgr to exit");

	if (shutdown_children_left() == 0) {
		log_info("shutdown complete");
		exit(0);
	}
	evtimer_set(&ev_shutdown, sigterm_force, NULL);
	tv.tv_sec = SHUTDOWN_TIMEOUT_SEC;
	tv.tv_usec = 0;
	evtimer_add(&ev_shutdown, &tv);
}

static void
sigchld_handler(int fd, short event, void *arg)
{
	pid_t	 pid;
	int	 status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		reap_child(pid, status);

	if (shutting_down && shutdown_children_left() == 0) {
		evtimer_del(&ev_shutdown);
		log_info("shutdown complete");
		exit(0);
	}
}

/*
 * Keymgr is not restarted, and worker exits are routine.
 */
static void
reap_child(pid_t pid, int status)
{
	struct open_session	*os;
	struct store_child	*sc, *s;
	struct child		*c;

	TAILQ_FOREACH(c, &children, entry) {
		if (c->pid == pid) {
			os = NULL;

			TAILQ_REMOVE(&children, c, entry);
			event_del(&c->iev.ev);
			if (c->iev.ibuf.fd != -1)
				close(c->iev.ibuf.fd);
			imsgbuf_clear(&c->iev.ibuf);

			if (c->type == PROC_KEYMGR) {
				/* Asked to go on shutdown, so not news. */
				if (shutting_down)
					log_debug("keymgr[%d] exited on "
					    "shutdown", pid);
				else if (WIFSIGNALED(status))
					log_warnx("keymgr[%d] terminated by "
					    "signal %d, TLS handshakes will "
					    "fail", pid, WTERMSIG(status));
				else if (WIFEXITED(status))
					log_warnx("keymgr[%d] exited, status "
					    "%d, TLS handshakes will fail",
					    pid, WEXITSTATUS(status));
				else
					log_warnx("keymgr[%d] exited, TLS "
					    "handshakes will fail", pid);
				iev_keymgr = NULL;
				certs_pending_clear();
				free(c);
				return;
			}

			if (c->type == PROC_PARSER) {
				log_debug("parser[%d] exited (status %d)",
				    pid, status);
				TAILQ_FOREACH(sc, &store_children, entry) {
					if (sc->parser_pid == pid)
						sc->parser_pid = 0;
				}
				free(c);
				return;
			}

			TAILQ_FOREACH(os, &open_sessions, entry) {
				if ((c->type == PROC_LISTENER &&
				    os->listener_pid == pid) ||
				    (c->type == PROC_AUTH &&
				    os->auth_pid == pid))
					break;
			}
			if (os == NULL) {
				log_debug("%s[%d] exited, no matching "
				    "open_session (already torn down)",
				    proc_name(c->type), pid);
				free(c);
				return;
			}

			if (c->type == PROC_LISTENER) {
				log_debug("session %u: listener-worker[%d] "
				    "exited (status %d), session closed",
				    os->session_id, pid, status);
				os->listener_iev = NULL;
				if ((s = os->store) != NULL) {
					os->store = NULL;
					store_child_session_gone(s);
				}
				TAILQ_REMOVE(&open_sessions, os, entry);
				free(os);
			} else {
				log_debug("session %u: auth-worker[%d] "
				    "exited, status %d",
				    os->session_id, pid, status);
				os->auth_iev = NULL;
				os->auth_pid = 0;
			}

			free(c);
			return;
		}
	}
	TAILQ_FOREACH(sc, &store_children, entry) {
		if (sc->pid == pid) {
			log_debug("session %u: store child exited "
			    "(status %d)", sc->session_id, status);
			store_child_teardown(sc, 1);
			return;
		}
	}
}
