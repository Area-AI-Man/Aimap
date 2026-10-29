PROG=		aimap

SRCS=		main.c parent.c log.c imsgev.c parse.y utf8.c mboxname.c \
		listener.c auth_cmd.c mailbox_cmd.c append_cmd.c fetch_cmd.c \
		search_cmd.c store_cmd.c store_ipc.c \
		auth.c \
		keymgr.c \
		parser.c \
		store.c index.c mime.c envelope.c mbox_fetch.c mbox_search.c \
		mbox_store.c mbox_manage.c mbox_copy.c search_match.c \
		store_cache.c

BINDIR=		/usr/local/sbin
MANDIR=		/usr/local/man/man

LDADD=		-levent -ltls -lssl -lcrypto -lutil
DPADD=		${LIBEVENT} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}

MAN=		aimap.8 aimap.conf.5

CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-align

EXAMPLEDIR=	/usr/local/share/examples/aimap

afterinstall:
	install -d -o root -g wheel -m 755 ${DESTDIR}${EXAMPLEDIR}
	install -c -o root -g bin -m 444 ${.CURDIR}/aimap.conf.example \
	    ${DESTDIR}${EXAMPLEDIR}/aimap.conf

.include <bsd.prog.mk>
