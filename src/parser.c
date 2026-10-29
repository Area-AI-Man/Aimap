#include <sys/types.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "store_internal.h"

static struct imsgev	 iev_store;

static void	 parser_dispatch_store(int, short, void *);
static int	 parser_spent(void);
static void	 parser_handle_request(struct imsgev *, struct imsg *,
		    uint32_t);
static int	 parser_search(struct ibuf *, const struct imsg_parser_req *,
		    int, char **, uint32_t *);

__dead void
parser_main(void)
{
	struct imsg_parser_init	 init;
	struct imsgbuf		 ibuf3;
	struct imsg		 imsg;
	gid_t			 gid;
	int			 n;
	int			 store_fd = -1;
	int			 got_init = 0;

	memset(&init, 0, sizeof(init));

	imsgev_ibuf_init(&ibuf3, 3);

	while (!got_init || store_fd == -1) {
		if ((n = imsgbuf_get(&ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0) {
			if ((n = imsgbuf_read(&ibuf3)) == -1)
				fatal("imsgbuf_read");
			if (n == 0)
				fatalx("parent closed channel before boot "
				    "finished");
			continue;
		}

		switch (imsg_get_type(&imsg)) {
		case IMSG_PARSER_INIT:
			if (imsg_get_data(&imsg, &init, sizeof(init)) == -1)
				fatalx("bad IMSG_PARSER_INIT payload");
			bodystructure_read_max = init.bodystructure_read_max;
			got_init = 1;
			break;
		case IMSG_SETUP_PEER:
			if (store_fd != -1) {
				log_warnx("duplicate IMSG_SETUP_PEER, "
				    "ignoring");
				break;
			}
			if ((store_fd = imsg_get_fd(&imsg)) == -1)
				fatalx("IMSG_SETUP_PEER carried no fd");
			break;
		default:
			log_debug("parser boot: unhandled %d",
			    imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}

	if (init.uid == 0 || init.gid == 0)
		fatalx("refusing to run as uid %u gid %u",
		    (unsigned int)init.uid, (unsigned int)init.gid);

	if (chroot(PATH_CHROOT) == -1)
		fatal("chroot %s", PATH_CHROOT);
	if (chdir("/") == -1)
		fatal("chdir /");

	/* A parse bug then reaches only this account. */
	gid = init.gid;
	if (setgroups(1, &gid) == -1 ||
	    setresgid(init.gid, init.gid, init.gid) == -1 ||
	    setresuid(init.uid, init.uid, init.uid) == -1)
		fatal("cannot drop privileges to uid %u gid %u",
		    (unsigned int)init.uid, (unsigned int)init.gid);

	setproctitle("parser uid %u", (unsigned int)init.uid);

	event_init();
	imsgev_init(&iev_store, store_fd, parser_dispatch_store, NULL);

	/* Files arrive as descriptors, so no rpath is needed. */
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
}

static void
parser_handle_request(struct imsgev *iev, struct imsg *imsg, uint32_t type)
{
	struct imsg_parser_req	 req;
	struct imsg_parser_rep	 rep;
	struct iovec		 iov[2];
	struct ibuf		 ibuf;
	uint32_t		 len = 0, cap = 0;
	char			*buf = NULL;
	int			 mfd, built = 0;

	mfd = imsg_get_fd(imsg);
	memset(&rep, 0, sizeof(rep));

	if (imsg_get_ibuf(imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &req, sizeof(req)) == -1)
		log_warnx("bad parser request %u", type);
	else if (mfd == -1)
		log_warnx("parser request %u carried no descriptor", type);
	else {
		req.basename[sizeof(req.basename) - 1] = '\0';
		req.fields[sizeof(req.fields) - 1] = '\0';
		switch (type) {
		case IMSG_PARSER_ENVELOPE:
			cap = ENVELOPE_MAX;
			built = build_envelope(mfd, req.basename, &buf,
			    &len) == 0;
			break;
		case IMSG_PARSER_BODYSTRUCTURE:
			cap = BODYSTRUCTURE_MAX;
			built = build_bodystructure(mfd, req.basename, &buf,
			    &len) == 0;
			break;
		case IMSG_PARSER_HEADER_FIELDS:
			cap = FETCH_HEADER_MAX;
			built = read_message_header_fields(mfd, req.basename,
			    req.fields, req.fields_not, &buf, &len) == 0;
			break;
		case IMSG_PARSER_SEARCH:
			cap = SEARCH_PROGRAM_MAX_NODES;
			built = parser_search(&ibuf, &req, mfd, &buf,
			    &len) == 0;
			break;
		case IMSG_PARSER_PART:
			/* Reply with the extent, not the octets. */
			if (req.pathlen >= 1 && req.pathlen <= MIME_MAX_DEPTH &&
			    extract_mime_part(mfd, req.basename, req.path,
			    req.pathlen, &rep.part_off, &rep.part_len) == 0)
				rep.found = 1;
			break;
		default:
			break;
		}
		if (built && len > 0 && len <= cap) {
			rep.found = 1;
			rep.len = len;
		}
	}
	if (mfd != -1)
		close(mfd);

	rep.retiring = parser_spent();
	iov[0].iov_base = &rep;
	iov[0].iov_len = sizeof(rep);
	iov[1].iov_base = buf;
	iov[1].iov_len = rep.found ? rep.len : 0;
	if (imsg_composev(&iev->ibuf, type, imsg_get_id(imsg), 0, -1, iov,
	    iov[1].iov_len > 0 ? 2 : 1) == -1)
		fatal("imsg_composev parser reply");
	free(buf);

	if (rep.retiring) {
		if (imsgbuf_flush(&iev->ibuf) == -1)
			fatal("imsgbuf_flush parser reply");
		log_debug("parser retiring after %d seconds of CPU",
		    PARSER_CPU_RETIRE_SEC);
		exit(0);
	}
}

static int
parser_search(struct ibuf *ibuf, const struct imsg_parser_req *req, int mfd,
    char **buf, uint32_t *len)
{
	const struct imsg_parser_leaf	*l;
	struct imsg_parser_leaf		 leaves[SEARCH_PROGRAM_MAX_NODES];
	uint32_t			 i;
	char				 pool[SEARCH_OPERANDS_MAX];

	if (req->nleaves == 0 || req->nleaves > SEARCH_PROGRAM_MAX_NODES ||
	    req->poollen > sizeof(pool) || ibuf_size(ibuf) !=
	    req->nleaves * sizeof(leaves[0]) + req->poollen ||
	    ibuf_get(ibuf, leaves, req->nleaves * sizeof(leaves[0])) == -1 ||
	    ibuf_get(ibuf, pool, req->poollen) == -1) {
		log_warnx("bad SEARCH request");
		return (-1);
	}
	for (i = 0; i < req->nleaves; i++) {
		l = &leaves[i];
		if (!search_op_content(l->op) || l->str_off > req->poollen ||
		    l->str_len > req->poollen - l->str_off ||
		    l->name_off > req->poollen ||
		    l->name_len > req->poollen - l->name_off) {
			log_warnx("bad SEARCH key %u", i);
			return (-1);
		}
	}
	return (search_match(mfd, req->basename, leaves, req->nleaves, pool,
	    buf, len));
}

static int
parser_spent(void)
{
	struct timeval	 tv;
	struct rusage	 ru;

	if (getrusage(RUSAGE_SELF, &ru) == -1)
		return (1);	/* Retire, a new parser is cheap. */
	timeradd(&ru.ru_utime, &ru.ru_stime, &tv);
	return (tv.tv_sec >= PARSER_CPU_RETIRE_SEC);
}

static void
parser_dispatch_store(int fd, short event, void *arg)
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
			log_debug("store closed channel, exiting");
			exit(0);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_PARSER_ENVELOPE:
		case IMSG_PARSER_BODYSTRUCTURE:
		case IMSG_PARSER_HEADER_FIELDS:
		case IMSG_PARSER_PART:
		case IMSG_PARSER_SEARCH:
			parser_handle_request(iev, &imsg,
			    imsg_get_type(&imsg));
			break;
		default:
			log_debug("unhandled request %d", imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}

	imsgev_rearm_read(iev);
}
