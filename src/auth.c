#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <libgen.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"

static struct imsgev	 iev_listener;
static struct imsgev	 iev_parent;
static char		 cred_file_basename[NAME_MAX + 1];

static int	 cred_lookup(const char *, const char *, char *, int *);
static int	 cred_cost(const char *);
static void	 auth_verify(struct imsg_auth_request *,
		    struct imsg_auth_result *);
static void	 auth_dispatch(int, short, void *);
static void	 auth_dispatch_parent(int, short, void *);
static int	 auth_session_already_resolved(uint32_t);
static void	 auth_session_mark_resolved(uint32_t);
static void	 auth_safe_name(const char *, char *, size_t);

/* After this many failures, every attempt fails unchecked. */
#define AUTH_MAX_TRIES	6
static unsigned int	 auth_failures;

/* Session IDs already answered, to refuse a replay. */
#define AUTH_RESOLVED_MAX	256
static uint32_t	 auth_resolved[AUTH_RESOLVED_MAX];
static size_t	 auth_resolved_next;
static int	 auth_resolved_full;

static int
auth_session_already_resolved(uint32_t sid)
{
	size_t	limit;
	size_t	i;

	limit = auth_resolved_full ? AUTH_RESOLVED_MAX : auth_resolved_next;
	for (i = 0; i < limit; i++) {
		if (auth_resolved[i] == sid)
			return (1);
	}
	return (0);
}

static void
auth_session_mark_resolved(uint32_t sid)
{
	auth_resolved[auth_resolved_next++] = sid;
	if (auth_resolved_next == AUTH_RESOLVED_MAX) {
		auth_resolved_next = 0;
		auth_resolved_full = 1;
	}
}

__dead void
auth_main(void)
{
	struct imsg_auth_init	 init;
	struct imsgbuf		 ibuf3;
	struct passwd		*pw;
	struct imsg		 imsg;
	char			*dir, *base;
	char			 unveil_path[PATH_MAX];
	int			 peer_fd;
	int			 n;

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
	if (imsg_get_type(&imsg) != IMSG_AUTH_INIT)
		fatalx("expected IMSG_AUTH_INIT, got %d",
		    imsg_get_type(&imsg));
	if (imsg_get_data(&imsg, &init, sizeof(init)) == -1)
		fatalx("bad IMSG_AUTH_INIT payload");
	/* The imsg data is not NUL-terminated. */
	init.cred_file[sizeof(init.cred_file) - 1] = '\0';
	imsg_free(&imsg);

	if ((pw = getpwnam(AIMAP_AUTH_USER)) == NULL)
		fatalx("unknown user %s", AIMAP_AUTH_USER);

	/* The parent sent a realpath(3) result, within PATH_MAX. */
	if ((dir = dirname(init.cred_file)) == NULL ||
	    (base = basename(init.cred_file)) == NULL)
		fatalx("cred_file: %s", init.cred_file);
	strlcpy(cred_file_basename, base, sizeof(cred_file_basename));

	if (chroot(dir) == -1)
		fatal("chroot %s", dir);
	if (chdir("/") == -1)
		fatal("chdir /");

	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("cannot drop privileges to _aimapauth");

	setproctitle("auth");

	peer_fd = setup_recv_one_peer(&ibuf3);

	event_init();
	imsgev_init(&iev_listener, peer_fd, auth_dispatch, NULL);

	imsgev_init_from_ibuf(&iev_parent, &ibuf3, auth_dispatch_parent, NULL);

	(void)snprintf(unveil_path, sizeof(unveil_path), "/%s",
	    cred_file_basename);
	if (unveil(unveil_path, "r") == -1)
		fatal("unveil %s", unveil_path);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil lock");

	/* The one descriptor arrived above, so no recvfd. */
	if (pledge("stdio rpath", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
}

static void
auth_dispatch(int fd, short event, void *arg)
{
	struct imsg_auth_request	 req;
	struct imsg_auth_result		 res;
	struct imsg_auth_cred		 cred;
	struct imsgev			*iev = arg;
	struct imsg			 imsg;
	int				 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			if (errno == EPIPE) {
				log_debug("auth-worker: listener closed "
				    "channel, exiting");
				exit(0);
			}
			fatal("imsgbuf_write");
		}
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0) {
			log_debug("auth-worker: listener closed channel, "
			    "exiting");
			exit(0);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_AUTH_REQUEST:
			if (imsg_get_data(&imsg, &req, sizeof(req)) == -1) {
				log_warnx("bad IMSG_AUTH_REQUEST");
				break;
			}
			req.username[sizeof(req.username) - 1] = '\0';
			req.password[sizeof(req.password) - 1] = '\0';

			setproctitle("session %u auth", req.session_id);

			if (auth_session_already_resolved(req.session_id)) {
				log_warnx("session %u: IMSG_AUTH_REQUEST: "
				    "already authenticated", req.session_id);
				explicit_bzero(req.password,
				    sizeof(req.password));
				break;
			}

			memset(&res, 0, sizeof(res));
			res.session_id = req.session_id;
			auth_verify(&req, &res);

			explicit_bzero(req.password, sizeof(req.password));

			if (imsg_compose(&iev->ibuf, IMSG_AUTH_RESULT, 0, 0,
			    -1, &res, sizeof(res)) == -1)
				log_warn("imsg_compose IMSG_AUTH_RESULT");

			if (res.ok) {
				auth_session_mark_resolved(res.session_id);

				memset(&cred, 0, sizeof(cred));
				cred.session_id = res.session_id;
				strlcpy(cred.username, req.username,
				    sizeof(cred.username));
				if (imsg_compose(&iev_parent.ibuf,
				    IMSG_AUTH_CRED, 0, 0, -1, &cred,
				    sizeof(cred)) == -1)
					log_warn("imsg_compose IMSG_AUTH_CRED");
			}
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

static void
auth_dispatch_parent(int fd, short event, void *arg)
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
			log_warnx("parent closed channel");
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		if (imsg_get_type(&imsg) == IMSG_AUTH_EXIT) {
			imsg_free(&imsg);
			/* The listener must have its answer before exit. */
			if (imsgbuf_flush(&iev_listener.ibuf) == -1)
				log_warn("imsgbuf_flush IMSG_AUTH_RESULT");
			log_debug("auth-worker: login granted, exiting");
			exit(0);
		}
		log_debug("%s: unhandled %d", __func__, imsg_get_type(&imsg));
		imsg_free(&imsg);
	}
	imsgev_rearm_read(iev);
}

/*
 * Every network-supplied user name reaches syslog through here.
 */
static void
auth_safe_name(const char *in, char *out, size_t outsize)
{
	unsigned char	 c;
	size_t		 i;

	for (i = 0; i + 1 < outsize && in[i] != '\0'; i++) {
		c = (unsigned char)in[i];

		out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
	}
	out[i] = '\0';
}

/*
 * Unknown users are hashed at the highest cost too.
 */
static void
auth_verify(struct imsg_auth_request *req, struct imsg_auth_result *res)
{
	const char	*hash = NULL;
	char		 cred[_PASSWORD_LEN];
	char		 dummy[_PASSWORD_LEN];
	char		 overname[AUTH_USERNAME_MAX];
	char		 safename[AUTH_USERNAME_MAX];
	int		 found, maxcost;

	if (auth_failures >= AUTH_MAX_TRIES) {
		res->ok = 0;
		auth_safe_name(req->username, overname, sizeof(overname));
		log_info("session %u: authentication failed for \"%s\" (over "
		    "AUTH_MAX_TRIES)", req->session_id, overname);
		return;
	}

	found = (cred_lookup(cred_file_basename, req->username, cred,
	    &maxcost) == 0);
	if (found)
		hash = cred;
	else if (maxcost > 0) {
		(void)snprintf(dummy, 8, "$2b$%02d$", maxcost);
		memset(dummy + 7, '.', 53);
		dummy[60] = '\0';
		hash = dummy;
	}

	if (crypt_checkpass(req->password, hash) == 0 && found)
		res->ok = 1;
	else {
		res->ok = 0;
		auth_failures++;
	}

	/* Log every outcome, for tools that watch failures. */
	auth_safe_name(req->username, safename, sizeof(safename));
	if (res->ok)
		log_info("session %u: authentication succeeded for \"%s\"",
		    req->session_id, safename);
	else
		log_info("session %u: authentication failed for \"%s\"",
		    req->session_id, safename);

	explicit_bzero(cred, sizeof(cred));
}

/*
 * A malformed hash fails fast, which timing would reveal.
 */
static int
cred_cost(const char *h)
{
	int	 cost;

	if (strlen(h) != 60 || h[0] != '$' || h[1] != '2' ||
	    (h[2] != 'a' && h[2] != 'b') || h[3] != '$' ||
	    !isdigit((unsigned char)h[4]) || !isdigit((unsigned char)h[5]) ||
	    h[6] != '$' || strspn(h + 7, "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789") != 53)
		return (0);
	cost = (h[4] - '0') * 10 + (h[5] - '0');
	return (cost >= 4 && cost <= 31 ? cost : 0);
}

/*
 * The file is a table(5), matched as smtpd(8) matches it.  Keys ignore case
 * and the last matching line wins.
 */
static int
cred_lookup(const char *path, const char *username, char *hash, int *maxcost)
{
	size_t	 linesize = 0;
	FILE	*fp;
	char	*line = NULL, *key, *val;
	int	 found = 0, lineno = 0, cost;

	*maxcost = 0;
	if ((fp = fopen(path, "r")) == NULL) {
		log_warn("fopen %s", path);
		return (-1);
	}
	if (check_file_secrecy(fileno(fp), path) == -1) {
		fclose(fp);
		return (-1);
	}

	while (getline(&line, &linesize, fp) != -1) {
		lineno++;
		/* A colon means the old format, not a hash. */
		if (table_line(line, &key, &val) == -1 ||
		    (key != NULL && strchr(val, ':') != NULL)) {
			log_warnx("%s:%d invalid map entry", path, lineno);
			found = 0;
			break;
		}
		if (key == NULL)
			continue;
		/* Values other than bcrypt, like "*", lock the account. */
		cost = cred_cost(val);
		if (cost > *maxcost)
			*maxcost = cost;
		if (strcasecmp(key, username) == 0)
			found = cost > 0 &&
			    strlcpy(hash, val, _PASSWORD_LEN) < _PASSWORD_LEN;
	}
	if (ferror(fp)) {
		log_warn("getline %s", path);
		found = 0;
	}

	freezero(line, linesize);
	fclose(fp);
	return (found ? 0 : -1);
}
