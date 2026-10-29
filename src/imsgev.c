/*
 * Copyright (c) 2009 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <sys/types.h>

#include <event.h>
#include <imsg.h>
#include <stdlib.h>

#include "aimap.h"
#include "log.h"

static void	 imsgev_add(struct imsgev *);
static void	 imsgev_on_compose(struct imsgbuf *, void *);
static int	 setup_recv_one_peer_id(struct imsgbuf *, uint32_t *);

void
imsgev_ibuf_init(struct imsgbuf *ibuf, int fd)
{
	if (imsgbuf_init(ibuf, fd) == -1)
		fatal("imsgbuf_init");
	if (imsgbuf_set_maxsize(ibuf, MAX_IMSGSIZE) == -1)
		fatal("imsgbuf_set_maxsize");
	imsgbuf_allow_fdpass(ibuf);
}

static void
imsgev_on_compose(struct imsgbuf *ibuf, void *arg)
{
	struct imsgev	*iev = arg;

	if (event_pending(&iev->ev, EV_WRITE, NULL))
		return;
	imsgev_add(iev);
}

void
imsgev_init(struct imsgev *iev, int fd, void (*handler)(int, short, void *),
    void *data)
{
	imsgev_ibuf_init(&iev->ibuf, fd);

	iev->handler = handler;
	iev->data = data != NULL ? data : iev;
	iev->events = EV_READ;

	event_set(&iev->ev, fd, iev->events, iev->handler, iev->data);
	event_add(&iev->ev, NULL);

	/* Set after imsgbuf_init(), which zeroes the struct. */
	imsgbuf_set_userdata(&iev->ibuf, iev);
	imsgbuf_set_close_callback(&iev->ibuf, imsgev_on_compose);
}

void
imsgev_init_from_ibuf(struct imsgev *iev, const struct imsgbuf *ibuf,
    void (*handler)(int, short, void *), void *data)
{
	iev->ibuf = *ibuf;

	iev->handler = handler;
	iev->data = data != NULL ? data : iev;
	iev->events = EV_READ;

	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler,
	    iev->data);
	event_add(&iev->ev, NULL);

	imsgbuf_set_userdata(&iev->ibuf, iev);
	imsgbuf_set_close_callback(&iev->ibuf, imsgev_on_compose);
}

/*
 * Without EV_PERSIST, each handler must add the event again.
 */
static void
imsgev_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf) > 0)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler,
	    iev->data);
	event_add(&iev->ev, NULL);
}

int
recv_fixed(struct imsg *imsg, void *data, size_t len, const char *what)
{
	if (imsg_get_data(imsg, data, len) == -1) {
		log_warnx("bad %s", what);
		return (0);
	}
	return (1);
}

int
recv_header(struct imsg *imsg, struct ibuf *ibuf, void *data, size_t len,
    const char *what)
{
	if (imsg_get_ibuf(imsg, ibuf) == -1 ||
	    ibuf_get(ibuf, data, len) == -1) {
		log_warnx("bad %s (header)", what);
		return (0);
	}
	return (1);
}

int
recv_chunk(struct imsg *imsg, char **bufp, size_t *lenp, size_t *gotp,
    const char *what)
{
	struct imsg_tls_chunk	 c;
	struct ibuf		 ibuf;
	size_t			 n;

	if (!recv_header(imsg, &ibuf, &c, sizeof(c), what))
		goto fail;
	if (c.offset == 0) {
		freezero(*bufp, *lenp);
		*bufp = NULL;
		*lenp = *gotp = 0;
		if (c.len > 0 && (*bufp = malloc(c.len)) == NULL) {
			log_warn("%s", what);
			return (-1);
		}
		*lenp = c.len;
	}
	n = ibuf_size(&ibuf);
	if (c.len != *lenp || c.offset != *gotp || n > c.len - c.offset) {
		log_warnx("bad %s (chunk)", what);
		goto fail;
	}
	if (n > 0 && ibuf_get(&ibuf, *bufp + c.offset, n) == -1) {
		log_warnx("bad %s (data)", what);
		goto fail;
	}
	*gotp += n;
	return (0);

fail:
	freezero(*bufp, *lenp);
	*bufp = NULL;
	*lenp = *gotp = 0;
	return (-1);
}

void
imsgev_rearm_read(struct imsgev *iev)
{
	imsgev_add(iev);
}

/*
 * Try imsgbuf_get() before imsgbuf_read(), since replies may coalesce.
 */
static int
setup_recv_one_peer_id(struct imsgbuf *ibuf3, uint32_t *id_out)
{
	struct imsg	 imsg;
	int		 n;
	int		 fd;

	for (;;) {
		if ((n = imsgbuf_get(ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n != 0)
			break;
		if ((n = imsgbuf_read(ibuf3)) == -1)
			fatal("imsgbuf_read");
		if (n == 0)
			fatalx("%s: parent closed channel", __func__);
	}

	if (imsg_get_type(&imsg) != IMSG_SETUP_PEER)
		fatalx("%s: expected IMSG_SETUP_PEER, got %d", __func__,
		    imsg_get_type(&imsg));

	if ((fd = imsg_get_fd(&imsg)) == -1)
		fatalx("%s: IMSG_SETUP_PEER carried no fd", __func__);

	if (id_out != NULL)
		*id_out = imsg_get_id(&imsg);

	imsg_free(&imsg);
	return (fd);
}

int
setup_recv_one_peer(struct imsgbuf *ibuf3)
{
	return (setup_recv_one_peer_id(ibuf3, NULL));
}

void
setup_recv_done_and_ack(struct imsgbuf *ibuf3)
{
	struct imsg	 imsg;
	int		 n;

	for (;;) {
		if ((n = imsgbuf_get(ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n != 0)
			break;
		if ((n = imsgbuf_read(ibuf3)) == -1)
			fatal("imsgbuf_read");
		if (n == 0)
			fatalx("%s: parent closed channel", __func__);
	}

	if (imsg_get_type(&imsg) != IMSG_SETUP_DONE)
		fatalx("%s: expected IMSG_SETUP_DONE, got %d", __func__,
		    imsg_get_type(&imsg));
	imsg_free(&imsg);

	if (imsg_compose(ibuf3, IMSG_SETUP_DONE, 0, 0, -1, NULL, 0) == -1)
		fatal("imsg_compose IMSG_SETUP_DONE");
	if (imsgbuf_flush(ibuf3) == -1)
		fatal("imsgbuf_flush");
}
