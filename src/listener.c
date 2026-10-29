/*
 * Copyright (c) 2021 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"

static struct session	 sess;	/* One process, one session */

struct imsgev	 iev_auth;
struct imsgev	 iev_parent;

static int	 auth_granted;

/* Read synchronously from OpenSSL callbacks, never dispatched. */
static struct imsgbuf	 keymgr_ibuf;

static struct tls_config	*listener_tls_config;
struct tls		*listener_tls_ctx;
uint32_t		 listener_idle_poll_secs = IDLE_POLL_DEFAULT;
uint32_t		 listener_login_grace_secs = LOGIN_GRACE_DEFAULT;
uint64_t		 listener_append_max = APPEND_MAX_DEFAULT;

struct imap_cmd_entry {
	const char	*name;
	unsigned int	 states;
	void		(*handler)(struct session *, const char *, char *);
};

#define ST_ANY \
	((1U << SESSION_NOT_AUTH) | (1U << SESSION_AUTHENTICATING) | \
	 (1U << SESSION_STORE_PENDING) | (1U << SESSION_AUTHENTICATED) | \
	 (1U << SESSION_SELECTING) | (1U << SESSION_SELECTED) | \
	 (1U << SESSION_FETCHING) | (1U << SESSION_STORING) | \
	 (1U << SESSION_EXPUNGING) | (1U << SESSION_APPENDING) | \
	 (1U << SESSION_SEARCHING) | \
	 (1U << SESSION_STATUSING) | \
	 (1U << SESSION_COPYING) | (1U << SESSION_CREATING) | \
	 (1U << SESSION_DELETING) | (1U << SESSION_RENAMING) | \
	 (1U << SESSION_LISTING) | (1U << SESSION_SUBSCRIBING) | \
	 (1U << SESSION_UNSUBSCRIBING))
#define ST_NOTAUTH	(1U << SESSION_NOT_AUTH)
#define ST_PREAUTH \
	(ST_NOTAUTH | (1U << SESSION_AUTHENTICATING) | \
	 (1U << SESSION_STORE_PENDING))

/* Transient states are left out, with a command pending. */
#define ST_AUTH \
	((1U << SESSION_AUTHENTICATED) | (1U << SESSION_SELECTED))
#define ST_SELECTED	(1U << SESSION_SELECTED)

static const struct imap_cmd_entry imap_cmds[] = {
	{ "CAPABILITY",	ST_ANY,		cmd_capability },
	{ "NOOP",	ST_ANY,		cmd_noop },
	{ "LOGOUT",	ST_ANY,		cmd_logout },
	{ "ID",		ST_ANY,		cmd_id },
	{ "LOGIN",	ST_NOTAUTH,	cmd_login },
	{ "STARTTLS",	ST_NOTAUTH,	cmd_starttls },
	{ "AUTHENTICATE", ST_NOTAUTH,	cmd_authenticate },

	/* Command-auth, in the order RFC 9051 lists them. */
	{ "ENABLE",	ST_AUTH,	cmd_enable },
	{ "SELECT",	ST_AUTH,	cmd_select },
	{ "EXAMINE",	ST_AUTH,	cmd_examine },
	{ "CREATE",	ST_AUTH,	cmd_create },
	{ "DELETE",	ST_AUTH,	cmd_delete },
	{ "RENAME",	ST_AUTH,	cmd_rename },
	{ "SUBSCRIBE",	ST_AUTH,	cmd_subscribe },
	{ "UNSUBSCRIBE", ST_AUTH,	cmd_unsubscribe },
	{ "LIST",	ST_AUTH,	cmd_list },
	{ "LSUB",	ST_AUTH,	cmd_lsub },
	{ "NAMESPACE",	ST_AUTH,	cmd_namespace },
	{ "STATUS",	ST_AUTH,	cmd_status },
	{ "APPEND",	ST_AUTH,	cmd_append },
	{ "IDLE",	ST_AUTH,	cmd_idle },

	/* Command-select, in the order RFC 9051 lists them. */
	{ "CLOSE",	ST_SELECTED,	cmd_close },
	{ "UNSELECT",	ST_SELECTED,	cmd_unselect },
	{ "EXPUNGE",	ST_SELECTED,	cmd_expunge },
	{ "SEARCH",	ST_SELECTED,	cmd_search },
	{ "FETCH",	ST_SELECTED,	cmd_fetch },
	{ "STORE",	ST_SELECTED,	cmd_store_cmd },
	{ "COPY",	ST_SELECTED,	cmd_copy },
	{ "MOVE",	ST_SELECTED,	cmd_move },
	{ "UID",	ST_SELECTED,	cmd_uid },
};

/* Exported by libtls, but declared in no installed header. */
void	tls_config_use_fake_private_key(struct tls_config *);

static void		 listener_dispatch_auth(int, short, void *);
static void		 listener_dispatch_parent(int, short, void *);
static void		 listener_start_session(uint32_t, int, int,
		    const struct sockaddr_storage *, socklen_t);
static void		 session_dispatch_client(int, short, void *);
static void		 session_tls_handshake(int, short, void *);
static void		 session_arm_client_read(struct session *);
static void		 session_send_greeting(struct session *);
static int		 session_is_busy(const struct session *);
static int		 session_enqueue_cmd(struct session *, const char *);
static void		 session_writef(struct session *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
static void		 session_handle_line(struct session *, char *);
static void		 session_cmd_clear(struct session *);
static int		 keymgr_set_fake_keypair(struct tls_config *,
		    const char *, size_t);
static int		 keymgr_wait_reply(uint32_t, uint32_t, const char *,
		    struct imsg *);
static int		 keymgr_forward_rsa(uint32_t, const char *,
		    const unsigned char *, int, unsigned char *, size_t, int);
static ECDSA_SIG	*keymgr_forward_ecdsa(const char *,
		    const unsigned char *, int);
static void		 keymgr_assert_fake_key(const char *, const BIGNUM *,
		    const char *);
static int		 keymgr_rsa_priv_enc(int, const unsigned char *,
		    unsigned char *, RSA *, int);
static int		 keymgr_rsa_priv_dec(int, const unsigned char *,
		    unsigned char *, RSA *, int);
static ECDSA_SIG	*keymgr_ecdsa_do_sign(const unsigned char *, int,
		    const BIGNUM *, const BIGNUM *, EC_KEY *);
static void		 keymgr_rsa_engine_init(void);
static void		 keymgr_ecdsa_engine_init(void);
static void		 keymgr_engine_init(void);
static void		 session_login_grace_expired(int, short, void *);
static void		 session_login_grace_init(struct session *);
static void		 session_login_grace_disarm(struct session *);
static int		 literal_count(const char *, uint64_t *, int *,
		    const char **);
static int		 line_literal(const char *, uint64_t *, int *);
static int		 line_nonsync_literal(const char *, uint64_t *);
static void		 session_cmd_reply(struct session *, const char *,
		    const char *);
static int		 session_gather(struct session *, uint64_t);
static void		 session_run_cmd(struct session *, char *);
static void		 session_queue(struct session *, const char *);
static int		 tag_is_valid(const char *);
static ssize_t		 session_read_client(struct session *, int, size_t *);
static int		 session_discard_literal(struct session *);
static int		 session_stream_append(struct session *);
static int		 session_gather_octets(struct session *);
static void		 session_route_line(struct session *, size_t, uint64_t);
static int		 session_consume_line(struct session *);
static int		 parse_command_line(char *, char **, char **, char **,
		    const char **);

static int
keymgr_set_fake_keypair(struct tls_config *config, const char *cert_buf,
    size_t cert_len)
{
	tls_config_use_fake_private_key(config);
	return (tls_config_set_keypair_mem(config,
	    (const uint8_t *)cert_buf, cert_len, NULL, 0));
}

/* This key is fake, so keymgr does private operations. */
static const RSA_METHOD	*keymgr_rsa_default;
static RSA_METHOD		*keymgr_rsae_method;
static const EC_KEY_METHOD	*keymgr_ecdsa_default;
static EC_KEY_METHOD		*keymgr_ecdsae_method;

static int
keymgr_wait_reply(uint32_t type, uint32_t id, const char *op,
    struct imsg *imsg)
{
	struct timespec	 start, now;
	struct pollfd	 pfd;
	int		 n;
	int		 ms;

	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		fatal("%s: clock_gettime", op);
	for (;;) {
		if ((n = imsgbuf_get(&keymgr_ibuf, imsg)) == -1)
			fatal("%s: imsgbuf_get", op);
		if (n != 0) {
			if (imsg_get_type(imsg) == type &&
			    imsg_get_id(imsg) == id)
				return (0);
			log_warnx("%s: unexpected reply type %u id %u "
			    "(wanted %u/%u)", op, imsg_get_type(imsg),
			    imsg_get_id(imsg), type, id);
			imsg_free(imsg);
			continue;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			fatal("%s: clock_gettime", op);
		ms = KEYMGR_REPLY_TIMEOUT_SEC * 1000 -
		    (int)((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000);
		if (ms <= 0) {
			log_warnx("%s: keymgr did not answer within %d "
			    "seconds", op, KEYMGR_REPLY_TIMEOUT_SEC);
			return (-1);
		}
		pfd.fd = keymgr_ibuf.fd;
		pfd.events = POLLIN;
		if ((n = poll(&pfd, 1, ms)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("%s: poll", op);
		}
		if (n == 0)
			continue;
		if ((n = imsgbuf_read(&keymgr_ibuf)) == -1)
			fatal("%s: imsgbuf_read", op);
		if (n == 0)
			fatalx("%s: keymgr closed channel", op);
	}
}

/*
 * Return as RSA_private_encrypt(3) does, -1 on error.
 */
static int
keymgr_forward_rsa(uint32_t type, const char *hash, const unsigned char *from,
    int fromlen, unsigned char *to, size_t tosize, int padding)
{
	struct imsg_keymgr_sign_request	 req;
	struct imsg_keymgr_sign_reply	 rep;
	static uint32_t			 reqid;
	struct iovec			 iov[2];
	struct imsg			 imsg;
	struct ibuf			 ibuf;
	uint32_t			 id;
	int				 ret;

	if (fromlen < 0 || (size_t)fromlen > KEYMGR_DATA_MAX) {
		log_warnx("%s: %d bytes over KEYMGR_DATA_MAX", __func__,
		    fromlen);
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	if (strlcpy(req.hash, hash, sizeof(req.hash)) >= sizeof(req.hash)) {
		log_warnx("%s: pubkey hash too long", __func__);
		return (-1);
	}
	req.padding = (uint32_t)padding;
	req.fromlen = (uint32_t)fromlen;

	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = (void *)from;
	iov[1].iov_len = (size_t)fromlen;

	id = ++reqid;
	if (imsg_composev(&keymgr_ibuf, type, id, 0, -1, iov,
	    fromlen > 0 ? 2 : 1) == -1) {
		log_warnx("%s: imsg_composev", __func__);
		return (-1);
	}
	if (imsgbuf_flush(&keymgr_ibuf) == -1)
		fatal("%s: imsgbuf_flush", __func__);

	if (keymgr_wait_reply(type, id, "keymgr_forward_rsa", &imsg) == -1)
		return (-1);
	if (imsg_get_ibuf(&imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &rep, sizeof(rep)) == -1) {
		log_warnx("%s: bad reply header", __func__);
		imsg_free(&imsg);
		return (-1);
	}
	ret = -1;
	if (rep.ok && rep.tolen <= tosize &&
	    ibuf_size(&ibuf) == rep.tolen) {
		if (ibuf_get(&ibuf, to, rep.tolen) == -1)
			log_warnx("%s: bad reply data", __func__);
		else
			ret = (int)rep.tolen;
	}
	imsg_free(&imsg);

	return (ret);
}

static ECDSA_SIG *
keymgr_forward_ecdsa(const char *hash, const unsigned char *dgst,
    int dgst_len)
{
	struct imsg_keymgr_sign_request	 req;
	struct imsg_keymgr_sign_reply	 rep;
	struct iovec			 iov[2];
	unsigned char			 sigbuf[KEYMGR_DATA_MAX];
	struct imsg			 imsg;
	struct ibuf			 ibuf;
	ECDSA_SIG			*sig = NULL;
	static uint32_t			 reqid;
	uint32_t			 id;
	const unsigned char		*sigp;

	if (dgst_len < 0 || (size_t)dgst_len > KEYMGR_DATA_MAX) {
		log_warnx("%s: %d bytes over KEYMGR_DATA_MAX", __func__,
		    dgst_len);
		return (NULL);
	}

	memset(&req, 0, sizeof(req));
	if (strlcpy(req.hash, hash, sizeof(req.hash)) >= sizeof(req.hash)) {
		log_warnx("%s: pubkey hash too long", __func__);
		return (NULL);
	}
	req.fromlen = (uint32_t)dgst_len;

	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = (void *)dgst;
	iov[1].iov_len = (size_t)dgst_len;

	id = ++reqid;
	if (imsg_composev(&keymgr_ibuf, IMSG_KEYMGR_ECDSA_SIGN, id, 0, -1,
	    iov, dgst_len > 0 ? 2 : 1) == -1) {
		log_warnx("%s: imsg_composev", __func__);
		return (NULL);
	}
	if (imsgbuf_flush(&keymgr_ibuf) == -1)
		fatal("%s: imsgbuf_flush", __func__);

	if (keymgr_wait_reply(IMSG_KEYMGR_ECDSA_SIGN, id,
	    "keymgr_forward_ecdsa", &imsg) == -1)
		return (NULL);
	if (imsg_get_ibuf(&imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &rep, sizeof(rep)) == -1) {
		log_warnx("%s: bad reply header", __func__);
		imsg_free(&imsg);
		return (NULL);
	}
	if (rep.ok && rep.tolen <= KEYMGR_DATA_MAX &&
	    ibuf_size(&ibuf) == rep.tolen) {
		if (ibuf_get(&ibuf, sigbuf, rep.tolen) == -1)
			log_warnx("%s: bad reply data", __func__);
		else {
			sigp = sigbuf;
			d2i_ECDSA_SIG(&sig, &sigp, (long)rep.tolen);
		}
	}
	imsg_free(&imsg);

	return (sig);
}

/*
 * A failure means privilege separation is not in effect.
 */
static void
keymgr_assert_fake_key(const char *hash, const BIGNUM *priv, const char *op)
{
	size_t	 i;

	/* The placeholder key has no private part. */
	if (priv != NULL)
		fatalx("%s: key object carries a private component", op);

	/* With one keypair, a missing tag is a regression. */
	if (hash == NULL)
		fatalx("%s: no pubkey-hash tag on the key object", op);

	for (i = 0; i < KEYMGR_HASH_MAX; i++)
		if (hash[i] == '\0')
			return;
	fatalx("%s: pubkey-hash tag not NUL-terminated within %d bytes",
	    op, KEYMGR_HASH_MAX);
}

static int
keymgr_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	const char	*hash;

	hash = RSA_get_ex_data(rsa, 0);
	keymgr_assert_fake_key(hash, RSA_get0_d(rsa), "RSA_PRIVENC");
	return (keymgr_forward_rsa(IMSG_KEYMGR_RSA_PRIVENC, hash,
	    from, flen, to, (size_t)RSA_size(rsa), padding));
}

static int
keymgr_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	const char	*hash;

	hash = RSA_get_ex_data(rsa, 0);
	keymgr_assert_fake_key(hash, RSA_get0_d(rsa), "RSA_PRIVDEC");
	return (keymgr_forward_rsa(IMSG_KEYMGR_RSA_PRIVDEC, hash,
	    from, flen, to, (size_t)RSA_size(rsa), padding));
}

static ECDSA_SIG *
keymgr_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
    const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
	const char	*hash;

	hash = EC_KEY_get_ex_data(eckey, 0);
	keymgr_assert_fake_key(hash, EC_KEY_get0_private_key(eckey),
	    "ECDSA_SIGN");
	return (keymgr_forward_ecdsa(hash, dgst, dgst_len));
}

static void
keymgr_rsa_engine_init(void)
{
	if ((keymgr_rsa_default = RSA_get_default_method()) == NULL)
		fatalx("%s: RSA_get_default_method", __func__);

	if ((keymgr_rsae_method = RSA_meth_dup(keymgr_rsa_default)) == NULL)
		fatalx("%s: RSA_meth_dup", __func__);

	RSA_meth_set_priv_enc(keymgr_rsae_method, keymgr_rsa_priv_enc);
	RSA_meth_set_priv_dec(keymgr_rsae_method, keymgr_rsa_priv_dec);

	RSA_meth_set_flags(keymgr_rsae_method,
	    RSA_meth_get_flags(keymgr_rsa_default) | RSA_METHOD_FLAG_NO_CHECK);
	RSA_meth_set0_app_data(keymgr_rsae_method,
	    RSA_meth_get0_app_data(keymgr_rsa_default));

	RSA_set_default_method(keymgr_rsae_method);
}

static void
keymgr_ecdsa_engine_init(void)
{
	int (*sign)(int, const unsigned char *, int, unsigned char *,
	    unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *);
	int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);

	if ((keymgr_ecdsa_default = EC_KEY_get_default_method()) == NULL)
		fatalx("%s: EC_KEY_get_default_method", __func__);

	if ((keymgr_ecdsae_method = EC_KEY_METHOD_new(keymgr_ecdsa_default))
	    == NULL)
		fatalx("%s: EC_KEY_METHOD_new", __func__);

	EC_KEY_METHOD_get_sign(keymgr_ecdsa_default, &sign, &sign_setup,
	    NULL);
	EC_KEY_METHOD_set_sign(keymgr_ecdsae_method, sign, sign_setup,
	    keymgr_ecdsa_do_sign);

	EC_KEY_set_default_method(keymgr_ecdsae_method);
}

static void
keymgr_engine_init(void)
{
	keymgr_rsa_engine_init();
	keymgr_ecdsa_engine_init();
}

__dead void
listener_main(void)
{
	struct imsg_listener_session_init	 sinit;
	struct imsgbuf				 ibuf3;
	struct passwd				*pw;
	struct imsg				 imsg;
	uint32_t				 id;
	size_t					 cert_len = 0, cert_got = 0;
	char					*cert = NULL;
	int					 auth_peer_fd = -1, peer_fd;
	int					 keymgr_peer_fd = -1;
	int					 client_fd = -1, n;
	int					 got_cert = 0;
	int					 got_session_init = 0;
	int					 got_keymgr_peer = 0;

	memset(&sinit, 0, sizeof(sinit));

	imsgev_ibuf_init(&ibuf3, 3);

	while (!got_cert || !got_session_init || !got_keymgr_peer) {
		if ((n = imsgbuf_get(&ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0) {
			if ((n = imsgbuf_read(&ibuf3)) == -1)
				fatal("imsgbuf_read");
			if (n == 0)
				fatalx("parent closed channel during boot");
			continue;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_SETUP_PEER:
			id = imsg_get_id(&imsg);
			peer_fd = imsg_get_fd(&imsg);
			if (peer_fd == -1) {
				log_warnx("listener: IMSG_SETUP_PEER "
				    "carried no fd");
				break;
			}
			if (id == 0) {
				if (auth_peer_fd != -1) {
					log_warnx("listener: duplicate auth "
					    "IMSG_SETUP_PEER, ignoring");
					close(peer_fd);
					break;
				}
				auth_peer_fd = peer_fd;
			} else {
				if (keymgr_peer_fd != -1) {
					log_warnx("listener: duplicate keymgr "
					    "IMSG_SETUP_PEER, ignoring");
					close(peer_fd);
					break;
				}
				keymgr_peer_fd = peer_fd;
				got_keymgr_peer = 1;
			}
			break;
		case IMSG_TLS_CERT:
			if (recv_chunk(&imsg, &cert, &cert_len, &cert_got,
			    "IMSG_TLS_CERT") == -1 || cert_got == cert_len)
				got_cert = 1;
			break;
		case IMSG_LISTENER_SESSION_INIT:
			if (imsg_get_data(&imsg, &sinit, sizeof(sinit))
			    == -1) {
				log_warnx("bad IMSG_LISTENER_SESSION_INIT");
				break;
			}
			if (client_fd != -1) {
				log_warnx("listener: duplicate "
				    "IMSG_LISTENER_SESSION_INIT, ignoring");
				break;
			}
			client_fd = imsg_get_fd(&imsg);
			got_session_init = 1;
			break;
		default:
			log_debug("listener boot: unhandled %d",
			    imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}

	if (client_fd == -1)
		fatalx("IMSG_LISTENER_SESSION_INIT carried no client fd");

	if ((pw = getpwnam(AIMAP_USER)) == NULL)
		fatalx("unknown user %s", AIMAP_USER);

	if (chroot(PATH_CHROOT) == -1)
		fatal("chroot %s", PATH_CHROOT);
	if (chdir("/") == -1)
		fatal("chdir /");

	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("cannot drop privileges to _aimap");

	keymgr_engine_init();

	/* No TLS rather than no daemon. */
	if (cert_len == 0) {
		log_warnx("session %u: no TLS cert received, TLS disabled",
		    sinit.session_id);
	} else if ((listener_tls_config = tls_config_new()) == NULL) {
		log_warnx("session %u: tls_config_new failed, TLS disabled",
		    sinit.session_id);
	} else if ((listener_tls_ctx = tls_server()) == NULL) {
		log_warnx("session %u: tls_server failed, TLS disabled",
		    sinit.session_id);
		tls_config_free(listener_tls_config);
		listener_tls_config = NULL;
	} else if (tls_config_set_ciphers(listener_tls_config, "secure")
	    != 0) {
		log_warnx("session %u: tls_config_set_ciphers: %s, "
		    "TLS disabled", sinit.session_id,
		    tls_config_error(listener_tls_config));
		tls_free(listener_tls_ctx);
		tls_config_free(listener_tls_config);
		listener_tls_ctx = NULL;
		listener_tls_config = NULL;
	} else if (keymgr_set_fake_keypair(listener_tls_config, cert,
	    cert_len) != 0) {
		log_warnx("session %u: tls_config_set_keypair_mem: %s, "
		    "TLS disabled", sinit.session_id,
		    tls_config_error(listener_tls_config));
		tls_free(listener_tls_ctx);
		tls_config_free(listener_tls_config);
		listener_tls_ctx = NULL;
		listener_tls_config = NULL;
	} else if (tls_configure(listener_tls_ctx, listener_tls_config)
	    != 0) {
		log_warnx("session %u: tls_configure: %s, TLS disabled",
		    sinit.session_id, tls_error(listener_tls_ctx));
		tls_free(listener_tls_ctx);
		tls_config_free(listener_tls_config);
		listener_tls_ctx = NULL;
		listener_tls_config = NULL;
	} else
		tls_config_clear_keys(listener_tls_config);
	free(cert);

	event_init();

	if (auth_peer_fd != -1)
		imsgev_init(&iev_auth, auth_peer_fd, listener_dispatch_auth,
		    NULL);
	else {
		iev_auth.ibuf.fd = -1;
		log_warnx("session %u: no auth-worker for this connection",
		    sinit.session_id);
	}

	if (imsgbuf_init(&keymgr_ibuf, keymgr_peer_fd) == -1)
		fatal("imsgbuf_init keymgr");
	imsgbuf_set_maxsize(&keymgr_ibuf, MAX_IMSGSIZE);

	/* Keep the bytes already buffered on fd 3. */
	imsgev_init_from_ibuf(&iev_parent, &ibuf3, listener_dispatch_parent,
	    NULL);

	listener_idle_poll_secs = sinit.idle_poll_secs;
	listener_login_grace_secs = sinit.login_grace_secs;
	listener_append_max = sinit.append_max;

	listener_start_session(sinit.session_id, client_fd,
	    sinit.implicit_tls, &sinit.remote_ss, sinit.remote_sslen);

	/* No inet, as getnameinfo(3) only formats numeric bytes. */
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
}

static void
session_login_grace_expired(int fd, short event, void *arg)
{
	struct session	*s = arg;

	log_info("session %u: closing peer=%.200s, no authentication within "
	    "%u seconds", s->id, s->remote_addr, listener_login_grace_secs);
	session_teardown(s, "login-grace");
}

static void
session_login_grace_init(struct session *s)
{
	struct timeval	 tv;

	evtimer_set(&s->grace_ev, session_login_grace_expired, s);
	if (listener_login_grace_secs == 0)
		return;		/* Zero disables it. */

	tv.tv_sec = (time_t)listener_login_grace_secs;
	tv.tv_usec = 0;
	if (evtimer_add(&s->grace_ev, &tv) == -1)
		log_warnx("session %u: evtimer_add (login grace)", s->id);
}

static void
session_login_grace_disarm(struct session *s)
{
	evtimer_del(&s->grace_ev);
}

static void
listener_start_session(uint32_t session_id, int client_fd, int implicit_tls,
    const struct sockaddr_storage *ss, socklen_t sslen)
{
	struct session	*s = &sess;
	char		 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	s->cmd.pending_body_fd = -1;	/* Zero is a real descriptor. */
	session_idle_poll_init(s);	/* Before anything can tear s down. */
	s->id = session_id;
	s->client_fd = client_fd;
	s->state = SESSION_NOT_AUTH;
	s->implicit_tls = implicit_tls;
	session_login_grace_init(s);
	if (clock_gettime(CLOCK_MONOTONIC, &s->connected_at) == -1)
		log_warn("session %u: clock_gettime", s->id);

	/* Numeric, so no resolver is used. */
	if (getnameinfo((const struct sockaddr *)ss, sslen, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
		snprintf(s->remote_addr, sizeof(s->remote_addr),
		    ss->ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s", hbuf,
		    sbuf);
	else
		strlcpy(s->remote_addr, "?", sizeof(s->remote_addr));

	/* Bound the peer text, and give tls as accepted. */
	log_info("session %u: connected peer=%.200s tls=%s", s->id,
	    s->remote_addr,
	    s->implicit_tls ? "implicit" : "none");

	/* Id and stage only, as anyone can read ps. */
	setproctitle("session %u [accepted]", s->id);

	if (s->implicit_tls) {
		if (listener_tls_ctx == NULL) {
			log_warnx("session %u: implicit-TLS port, but TLS "
			    "isn't configured, closing", s->id);
			session_teardown(s, "tls-error");
		}
		s->pending_greeting = 1;
		session_tls_start(s);
		return;
	}

	session_arm_client_read(s);
	session_send_greeting(s);
}

static void
session_arm_client_read(struct session *s)
{
	if (s->client_ev_added)
		event_del(&s->client_ev);
	event_set(&s->client_ev, s->client_fd, EV_READ | EV_PERSIST,
	    session_dispatch_client, s);
	event_add(&s->client_ev, NULL);
	s->client_ev_added = 1;
}

void
session_tls_start(struct session *s)
{
	if (tls_accept_socket(listener_tls_ctx, &s->tls_ctx, s->client_fd)
	    != 0) {
		log_warnx("session %u: tls_accept_socket: %s", s->id,
		    tls_error(listener_tls_ctx));
		session_teardown(s, "tls-error");
	}

	if (s->client_ev_added)
		event_del(&s->client_ev);
	event_set(&s->client_ev, s->client_fd, EV_READ, session_tls_handshake,
	    s);
	event_add(&s->client_ev, NULL);
	s->client_ev_added = 1;
}

static void
session_tls_handshake(int fd, short event, void *arg)
{
	struct session	*s = arg;
	int		 ret;

	ret = tls_handshake(s->tls_ctx);
	if (ret == 0) {
		s->tls_active = 1;
		log_debug("session %u: TLS handshake complete (%s %s)",
		    s->id, tls_conn_version(s->tls_ctx),
		    tls_conn_cipher(s->tls_ctx));
		session_arm_client_read(s);
		if (s->pending_greeting) {
			s->pending_greeting = 0;
			session_send_greeting(s);
		}
		return;
	}
	if (ret == TLS_WANT_POLLIN) {
		event_del(&s->client_ev);
		event_set(&s->client_ev, s->client_fd, EV_READ,
		    session_tls_handshake, s);
		event_add(&s->client_ev, NULL);
		return;
	}
	if (ret == TLS_WANT_POLLOUT) {
		event_del(&s->client_ev);
		event_set(&s->client_ev, s->client_fd, EV_WRITE,
		    session_tls_handshake, s);
		event_add(&s->client_ev, NULL);
		return;
	}

	log_warnx("session %u: tls_handshake: %s (peer %s)", s->id,
	    tls_error(s->tls_ctx), s->remote_addr);
	session_teardown(s, "tls-error");
}

static void
session_send_greeting(struct session *s)
{
	static const char	 greeting[] = "* OK aimap ready\r\n";

	session_write(s, greeting, sizeof(greeting) - 1);
}

/* A non-synchronizing literal has at most 4096 octets. */
#define IMAP_NONSYNC_LITERAL_MAX	4096

/*
 * Parse "{n}" or "{n+}" at p.  *endp is set past the "}".
 */
static int
literal_count(const char *p, uint64_t *lenp, int *nonsyncp, const char **endp)
{
	const char	*errstr;
	long long	 v;
	size_t		 dlen;
	char		 digits[24];

	if (*p++ != '{')
		return (0);
	dlen = strspn(p, "0123456789");
	if (dlen == 0 || dlen >= sizeof(digits))
		return (0);
	memcpy(digits, p, dlen);
	digits[dlen] = '\0';
	v = strtonum(digits, 0, LLONG_MAX, &errstr);
	if (errstr != NULL)
		return (0);
	p += dlen;
	*nonsyncp = (*p == '+');
	if (*nonsyncp)
		p++;
	if (*p != '}')
		return (0);
	*lenp = (uint64_t)v;
	*endp = p + 1;
	return (1);
}

static int
line_literal(const char *line, uint64_t *lenp, int *nonsyncp)
{
	const char	*open, *end;
	size_t		 len;

	len = strlen(line);
	if (len < 3 || line[len - 1] != '}' ||
	    (open = memrchr(line, '{', len)) == NULL)
		return (0);
	return (literal_count(open, lenp, nonsyncp, &end) && *end == '\0');
}

static int
line_nonsync_literal(const char *line, uint64_t *lenp)
{
	int	nonsync;

	if (!line_literal(line, lenp, &nonsync) || !nonsync) {
		*lenp = 0;
		return (0);
	}
	return (1);
}

const char	literal_wanted[] = "literal wanted";

/*
 * Read a literal inside a gathered command.  If it ends the text, ask for
 * it.
 */
int
read_literal(char **pp, char **datap, size_t *lenp, const char **errmsg)
{
	const char	*end;
	uint64_t	 n;
	int		 nonsync;

	if (!literal_count(*pp, &n, &nonsync, &end)) {
		*errmsg = "malformed literal";
		return (-1);
	}
	if (*end == '\0') {
		*errmsg = literal_wanted;
		return (-1);
	}
	if (end[0] != '\r' || end[1] != '\n' ||
	    (uint64_t)strlen(end + 2) < n) {
		*errmsg = "malformed literal";
		return (-1);
	}
	*datap = *pp + (end + 2 - *pp);
	*lenp = (size_t)n;
	*pp = *datap + *lenp;
	return (0);
}

/*
 * SP is exactly one space, never at the end.
 */
int
read_sp(char **pp, const char **errmsg)
{
	if (**pp != ' ') {
		*errmsg = "missing space";
		return (-1);
	}
	if ((*pp)[1] == ' ' || (*pp)[1] == '\0') {
		*errmsg = "extra space";
		return (-1);
	}
	(*pp)++;
	return (0);
}

/*
 * Terminate the word at *pp.  Move *pp past exactly one SP, or to the end.
 */
int
next_word(char **pp, char **wordp, const char **errmsg)
{
	char	*p = *pp;

	*wordp = p;
	while (*p != '\0' && *p != ' ')
		p++;
	if (*p == ' ') {
		if (read_sp(&p, errmsg) == -1) {
			/* A BAD reply still quotes the tag. */
			*p = '\0';
			return (-1);
		}
		p[-1] = '\0';
	}
	*pp = p;
	return (0);
}

/*
 * Read the quoted string at p.  Keep up to outsize bytes, unterminated.
 */
int
read_quoted(const char *p, char *out, size_t outsize, size_t *lenp,
    size_t *usedp, const char **errmsg)
{
	const char	*start = p;
	size_t		 n = 0;

	for (p++; *p != '"'; p++) {
		if (*p == '\\' && *++p != '"' && *p != '\\' && *p != '\0') {
			*errmsg = "invalid escape in quoted string";
			return (-1);
		}
		if (*p == '\0') {
			*errmsg = "unterminated quoted string";
			return (-1);
		}
		if (n < outsize)
			out[n] = *p;
		n++;
	}
	*lenp = n;
	*usedp = (size_t)(p + 1 - start);
	return (0);
}

/*
 * Return the ")" closing "(" at p, or NULL.
 */
char *
match_paren(char *p)
{
	int	 depth = 0;

	for (;; p++) {
		if (*p == '(')
			depth++;
		else if (*p == ')') {
			if (--depth == 0)
				return (p);
		} else if (*p == '\0')
			return (NULL);
	}
}

const char *
mbox_error_text(enum mbox_op_error error, const char *cmdname, char *buf,
    size_t bufsize)
{
	switch (error) {
	case MBOX_OP_ERR_BUSY:
		return (IMAP_BUSY_TEXT);
	case MBOX_OP_ERR_NO_SUCH_MAILBOX:
		return ("[NONEXISTENT] no such mailbox");
	case MBOX_OP_ERR_ALREADY_EXISTS:
		return ("[ALREADYEXISTS] mailbox already exists");
	case MBOX_OP_ERR_OVERQUOTA:
		return (IMAP_OVERQUOTA_TEXT);
	case MBOX_OP_ERR_EXPUNGEISSUED:
		snprintf(buf, bufsize, "[EXPUNGEISSUED] %s failed", cmdname);
		break;
	case MBOX_OP_ERR_LIMIT:
		snprintf(buf, bufsize, "[LIMIT] %s failed", cmdname);
		break;
	default:
		snprintf(buf, bufsize, "%s failed", cmdname);
		break;
	}
	return (buf);
}

/*
 * Reply BAD, unless the argument waits for a literal.
 */
void
session_arg_error(struct session *s, const char *tag, const char *errmsg)
{
	if (errmsg == literal_wanted)
		s->wants_literal = 1;
	else
		session_reply(s, tag, "BAD", errmsg);
}

static const char cmd_too_long[] = "[LIMIT] command with its literals "
    "exceeds 8191 octets";

static void
session_cmd_reply(struct session *s, const char *status, const char *text)
{
	size_t	 len;
	char	 tag[IMAP_TAG_MAX];

	len = strcspn(s->cmdbuf, " ");
	if (len >= sizeof(tag))
		len = sizeof(tag) - 1;
	memcpy(tag, s->cmdbuf, len);
	tag[len] = '\0';
	session_reply(s, len > 0 ? tag : "*", status, text);
}

/*
 * Append the next literal to cmdbuf, or refuse it.
 */
static int
session_gather(struct session *s, uint64_t n)
{
	if (s->cmdlen + 3 > sizeof(s->cmdbuf) ||
	    n > sizeof(s->cmdbuf) - 3 - s->cmdlen) {
		session_cmd_reply(s, "NO", cmd_too_long);
		s->cmd_queued = 0;
		return (0);
	}
	memcpy(s->cmdbuf + s->cmdlen, "\r\n", 2);
	s->cmdlen += 2;
	s->cmd_octets = (size_t)n;
	s->cmd_gather = 1;
	return (1);
}

/*
 * Run a command, reparsed as each literal arrives.
 */
static void
session_run_cmd(struct session *s, char *cmd)
{
	static const char	 cont[] = "+ Ready for literal data\r\n";
	static char		 cmdwork[SESSION_INBUF_MAX];
	uint64_t		 n;
	int			 nonsync;

	if (!line_literal(cmd, &n, &nonsync)) {
		session_handle_line(s, cmd);
		return;
	}
	if (cmd != s->cmdbuf)
		(void)strlcpy(s->cmdbuf, cmd, sizeof(s->cmdbuf));
	(void)strlcpy(cmdwork, s->cmdbuf, sizeof(cmdwork));
	s->wants_literal = 0;
	session_handle_line(s, cmdwork);
	if (!s->wants_literal)
		return;
	s->wants_literal = 0;
	s->cmdlen = strlen(s->cmdbuf);
	if (session_gather(s, n) && !nonsync)
		session_write(s, cont, sizeof(cont) - 1);
}

static void
session_queue(struct session *s, const char *cmd)
{
	static const char	 bad[] = "* BAD too many pipelined commands, "
	    "closing connection\r\n";

	if (session_enqueue_cmd(s, cmd))
		return;
	log_warnx("session %u: pipelined command queue full, closing", s->id);
	session_write(s, bad, sizeof(bad) - 1);
	session_teardown(s, "limit-exceeded");
}

/*
 * Tag characters are ASTRING-CHAR, except "+".
 */
static int
tag_is_valid(const char *tag)
{
	const unsigned char	*p;

	if (*tag == '\0')
		return (0);
	for (p = (const unsigned char *)tag; *p != '\0'; p++) {
		if (*p <= 0x20 || *p >= 0x7f)
			return (0);
		if (strchr("(){%*\"\\+", (int)*p) != NULL)
			return (0);
	}
	return (1);
}

/*
 * Return octets read into inbuf, or -1 to retry.
 */
static ssize_t
session_read_client(struct session *s, int fd, size_t *tls_wantp)
{
	ssize_t	n;

	*tls_wantp = 0;
	if (s->tls_active) {
		*tls_wantp = sizeof(s->inbuf) - s->inbuflen;
		n = tls_read(s->tls_ctx, s->inbuf + s->inbuflen, *tls_wantp);
		if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
			/* A TLS read may need to write. */
			event_del(&s->client_ev);
			event_set(&s->client_ev, s->client_fd,
			    (n == TLS_WANT_POLLIN) ? EV_READ : EV_WRITE,
			    session_dispatch_client, s);
			event_add(&s->client_ev, NULL);
			return (-1);
		}
		if (n == -1) {
			log_warnx("session %u: tls_read: %s", s->id,
			    tls_error(s->tls_ctx));
			session_teardown(s, "tls-error");
		}
		session_arm_client_read(s);
	} else {
		n = read(fd, s->inbuf + s->inbuflen,
		    sizeof(s->inbuf) - s->inbuflen);
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				return (-1);
			log_warn("session %u: read", s->id);
			session_teardown(s, "io-error");
		}
	}
	if (n == 0) {
		log_debug("session %u: client closed connection", s->id);
		session_teardown(s, "client-closed");
	}
	return (n);
}

/*
 * Return 1 once discarded, or 0 for more input.
 */
static int
session_discard_literal(struct session *s)
{
	uint64_t	take;

	take = (uint64_t)s->inbuflen < s->literal_discard ?
	    (uint64_t)s->inbuflen : s->literal_discard;
	if (take > 0) {
		memmove(s->inbuf, s->inbuf + take, s->inbuflen - (size_t)take);
		s->inbuflen -= (size_t)take;
		s->literal_discard -= take;
	}
	if (s->literal_discard > 0)
		return (0);
	s->literal_skipline = 1;
	return (1);
}

/*
 * Append literal octets, which may contain a CRLF.
 */
static int
session_stream_append(struct session *s)
{
	uint64_t	want, take;

	want = s->literal_remaining;
	take = (uint64_t)s->inbuflen < want ? (uint64_t)s->inbuflen : want;
	if (take > 0) {
		if (imsg_compose(&s->store_iev->ibuf, IMSG_MBOX_APPEND_DATA,
		    0, 0, -1, s->inbuf, (size_t)take) == -1) {
			log_warn("session %u: imsg_compose "
			    "IMSG_MBOX_APPEND_DATA", s->id);
			session_teardown(s, "io-error");
		}
		s->literal_remaining -= take;
		memmove(s->inbuf, s->inbuf + take, s->inbuflen - (size_t)take);
		s->inbuflen -= (size_t)take;
	}
	if (s->literal_remaining > 0)
		return (0);

	if (s->inbuflen < 2)
		return (0);
	if (s->inbuf[0] != '\r' || s->inbuf[1] != '\n') {
		/* No reliable resync point exists, so give up. */
		log_warnx("session %u: expected CRLF after literal data, "
		    "closing", s->id);
		session_teardown(s, "protocol-error");
	}
	memmove(s->inbuf, s->inbuf + 2, s->inbuflen - 2);
	s->inbuflen -= 2;

	s->literal_pending = 0;
	session_finish_append(s);
	return (1);
}

static int
session_gather_octets(struct session *s)
{
	size_t	take;

	take = s->inbuflen < s->cmd_octets ? s->inbuflen : s->cmd_octets;
	if (take == 0)
		return (0);
	if (memchr(s->inbuf, '\0', take) != NULL) {
		session_cmd_reply(s, "BAD", "NUL in a literal");
		s->literal_discard = s->cmd_octets;
		s->cmd_gather = 0;
		s->cmd_queued = 0;
		s->cmd_octets = 0;
		return (1);
	}
	memcpy(s->cmdbuf + s->cmdlen, s->inbuf, take);
	s->cmdlen += take;
	s->cmd_octets -= take;
	memmove(s->inbuf, s->inbuf + take, s->inbuflen - take);
	s->inbuflen -= take;
	return (1);
}

static void
session_route_line(struct session *s, size_t linelen, uint64_t nonsync_len)
{
	int	resume;

	resume = 0;
	if (s->literal_skipline) {
		s->literal_skipline = 0;
		resume = 1;
	} else if (s->cmd_gather) {
		s->cmd_gather = 0;
		if (linelen >= sizeof(s->cmdbuf) - s->cmdlen) {
			session_cmd_reply(s, "NO", cmd_too_long);
			s->cmd_queued = 0;
		} else {
			memcpy(s->cmdbuf + s->cmdlen, s->inbuf, linelen + 1);
			if (!s->cmd_queued)
				session_run_cmd(s, s->cmdbuf);
			else if (nonsync_len > 0) {
				s->cmdlen += linelen;
				(void)session_gather(s, nonsync_len);
			} else {
				s->cmd_queued = 0;
				session_queue(s, s->cmdbuf);
			}
		}
		resume = 1;
	} else if (s->auth_cont) {
		/* The line is a base64 password, scrubbed after use. */
		s->scrub_inbuf = 1;
		session_handle_auth_continuation(s, s->inbuf);
	} else if (s->idling)
		session_handle_idle_continuation(s, s->inbuf);
	else if (session_is_busy(s)) {
		/* Queue while another command is in flight. */
		if (nonsync_len > 0) {
			(void)strlcpy(s->cmdbuf, s->inbuf, sizeof(s->cmdbuf));
			s->cmdlen = strlen(s->cmdbuf);
			s->cmd_queued = 1;
			(void)session_gather(s, nonsync_len);
		} else
			session_queue(s, s->inbuf);
	} else
		session_run_cmd(s, s->inbuf);
	if (resume && nonsync_len == 0)
		session_dequeue_next(s);
}

static int
session_consume_line(struct session *s)
{
	static const char	 bad[] = "* BAD bare CR, LF or NUL "
	    "in command line, closing connection\r\n";
	static const char	 bye[] = "* BYE [TOOBIG] "
	    "non-synchronizing literal exceeds 4096 octets\r\n";
	uint64_t		 nonsync_len;
	size_t			 consumed, linelen;
	char			*crlf;

	crlf = memmem(s->inbuf, s->inbuflen, "\r\n", 2);
	if (crlf == NULL)
		return (0);
	linelen = (size_t)(crlf - s->inbuf);
	consumed = linelen + 2;

	/* A line may not hold CR, LF or NUL. */
	if (memchr(s->inbuf, '\r', linelen) != NULL ||
	    memchr(s->inbuf, '\n', linelen) != NULL ||
	    memchr(s->inbuf, '\0', linelen) != NULL) {
		log_warnx("session %u: bare CR/LF/NUL in command "
		    "line, closing", s->id);
		session_write(s, bad, sizeof(bad) - 1);
		session_teardown(s, "protocol-error");
	}
	*crlf = '\0';

	nonsync_len = 0;
	if (line_nonsync_literal(s->inbuf, &nonsync_len) &&
	    nonsync_len > IMAP_NONSYNC_LITERAL_MAX) {
		log_warnx("session %u: oversized non-synchronizing "
		    "literal (%llu), closing", s->id,
		    (unsigned long long)nonsync_len);
		session_write(s, bye, sizeof(bye) - 1);
		session_teardown(s, "limit-exceeded");
	}

	session_route_line(s, linelen, nonsync_len);

	if (nonsync_len > 0 && !s->literal_pending && !s->cmd_gather)
		s->literal_discard = nonsync_len;

	/* STARTTLS may have emptied inbuf. */
	if (consumed > s->inbuflen)
		consumed = s->inbuflen;

	/* Do not leave a password in inbuf. */
	if (s->scrub_inbuf) {
		explicit_bzero(s->inbuf, consumed);
		s->scrub_inbuf = 0;
	}

	memmove(s->inbuf, s->inbuf + consumed, s->inbuflen - consumed);
	s->inbuflen -= consumed;
	return (1);
}

static void
session_dispatch_client(int fd, short event, void *arg)
{
	struct session		*s = arg;
	static const char	 bad[] = "* BAD command line too long\r\n";
	ssize_t			 n;
	size_t			 tls_want;
	int			 rc;

	if (s->write_failed)
		session_teardown(s, "io-error");
	if ((n = session_read_client(s, fd, &tls_want)) == -1)
		return;
	s->inbuflen += (size_t)n;

	for (;;) {
		if (s->literal_discard > 0)
			rc = session_discard_literal(s);
		else if (s->literal_pending)
			rc = session_stream_append(s);
		else if (s->cmd_gather && s->cmd_octets > 0)
			rc = session_gather_octets(s);
		else
			rc = session_consume_line(s);
		if (rc == -1)
			return;
		if (rc == 0)
			break;
	}

	if (s->inbuflen == sizeof(s->inbuf)) {
		log_warnx("session %u: command line too long, closing",
		    s->id);
		session_write(s, bad, sizeof(bad) - 1);
		session_teardown(s, "limit-exceeded");
	}

	/* TLS may buffer bytes that EV_READ will not report. */
	if (s->tls_active && (size_t)n == tls_want &&
	    s->inbuflen < sizeof(s->inbuf))
		event_active(&s->client_ev, EV_READ, 1);
}

/* Short before login, and 30 minutes after. */
#define SESSION_WRITE_PREAUTH_MS	5000
#define SESSION_WRITE_AUTH_MS		(1800 * 1000)

void
session_write(struct session *s, const char *buf, size_t len)
{
	struct pollfd	pfd;
	ssize_t		n;
	size_t		sent = 0, dlen, i;
	char		dbuf[301];
	int		timeout, pret;

	if (s->write_failed)
		return;
	timeout = (ST_PREAUTH & (1U << s->state)) ?
	    SESSION_WRITE_PREAUTH_MS : SESSION_WRITE_AUTH_MS;

	if (log_getverbose() > 0) {
		dlen = len < sizeof(dbuf) - 1 ? len : sizeof(dbuf) - 1;

		memcpy(dbuf, buf, dlen);
		dbuf[dlen] = '\0';
		for (i = 0; i < dlen; i++)
			if (dbuf[i] == '\r' || dbuf[i] == '\n')
				dbuf[i] = ' ';
		log_debug("session %u: >>> %s%s", s->id, dbuf,
		    len > dlen ? "...(truncated)" : "");
	}

	if (!s->tls_active) {
		while (sent < len) {
			n = write(s->client_fd, buf + sent, len - sent);
			if (n == -1) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					pfd.fd = s->client_fd;
					pfd.events = POLLOUT;
					if (poll(&pfd, 1, timeout) <= 0) {
						log_warnx("session %u: write: "
						    "timed out or poll error",
						    s->id);
						goto fail;
					}
					continue;
				}
				log_warn("session %u: write", s->id);
				goto fail;
			}
			sent += (size_t)n;
		}
		return;
	}

	while (sent < len) {
		n = tls_write(s->tls_ctx, buf + sent, len - sent);
		if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
			pfd.fd = s->client_fd;
			pfd.events = (n == TLS_WANT_POLLIN) ? POLLIN : POLLOUT;
			pret = poll(&pfd, 1, timeout);
			if (pret == -1) {
				log_warn("session %u: poll (tls_write retry)",
				    s->id);
				goto fail;
			}
			if (pret == 0) {
				log_warnx("session %u: tls_write: timed out "
				    "waiting for socket", s->id);
				goto fail;
			}
			continue;
		}
		if (n == -1) {
			log_warnx("session %u: tls_write: %s", s->id,
			    tls_error(s->tls_ctx));
			goto fail;
		}
		sent += (size_t)n;
	}
	return;

fail:
	s->write_failed = 1;
	/* The client may never send again, so wake now. */
	event_active(&s->client_ev, EV_READ, 1);
}

/*
 * On overflow the line still ends in CRLF.
 */
static void
session_writef(struct session *s, const char *fmt, ...)
{
	va_list	ap;
	char	buf[512];
	int	len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len < 0)
		return;
	if ((size_t)len >= sizeof(buf)) {
		buf[sizeof(buf) - 3] = '\r';
		buf[sizeof(buf) - 2] = '\n';
		len = sizeof(buf) - 1;
	}
	session_write(s, buf, (size_t)len);
}

void
session_reply(struct session *s, const char *tag, const char *status,
    const char *text)
{
	session_writef(s, "%s %s %s\r\n", tag, status, text);
}

void
session_untagged(struct session *s, const char *text)
{
	session_writef(s, "* %s\r\n", text);
}

int
send_mbox_request(struct session *s, int imsg_type, const char *imsgname,
    const void *req, size_t reqlen, const void *elems, uint32_t nelems,
    size_t elemsize)
{
	struct iovec	 iov[2];

	iov[0].iov_base = (void *)req;
	iov[0].iov_len = reqlen;
	iov[1].iov_base = (void *)elems;
	iov[1].iov_len = (size_t)nelems * elemsize;
	if (imsg_composev(&s->store_iev->ibuf, imsg_type, 0, 0, -1, iov,
	    iov[1].iov_len > 0 ? 2 : 1) == -1) {
		log_warn("session %u: imsg_composev %s", s->id, imsgname);
		return (-1);
	}
	return (0);
}

void
session_condstore_enable(struct session *s)
{
	char	buf[48];

	if (s->condstore_enabled)
		return;
	s->condstore_enabled = 1;

	if (s->state == SESSION_SELECTED) {
		snprintf(buf, sizeof(buf), "OK [HIGHESTMODSEQ %llu]",
		    (unsigned long long)s->mbox_highestmodseq);
		session_untagged(s, buf);
	}
}

/*
 * With no readable tag, return -1 with *tag NULL.  The answer is then
 * untagged.
 */
static int
parse_command_line(char *line, char **tag, char **name, char **args,
    const char **errmsg)
{
	char	*p = line;

	*tag = NULL;
	*name = NULL;
	*args = NULL;
	if (*p == '\0' || *p == ' ') {
		*errmsg = (*p == '\0') ? "empty command line" : "extra space";
		return (-1);
	}
	if (next_word(&p, tag, errmsg) == -1)
		return (-1);
	if (*p == '\0')
		return (0);
	if (next_word(&p, name, errmsg) == -1)
		return (-1);
	if (*p != '\0')
		*args = p;
	return (0);
}

static int
session_is_busy(const struct session *s)
{
	if (s->cmd.refresh_status != NULL)
		return (1);
	switch (s->state) {
	case SESSION_SELECTING:
	case SESSION_FETCHING:
	case SESSION_STORING:
	case SESSION_EXPUNGING:
	case SESSION_APPENDING:
	case SESSION_SEARCHING:
	case SESSION_STATUSING:
	case SESSION_COPYING:
	case SESSION_CREATING:
	case SESSION_DELETING:
	case SESSION_RENAMING:
	case SESSION_LISTING:
	case SESSION_SUBSCRIBING:
	case SESSION_UNSUBSCRIBING:
		return (1);
	default:
		return (0);
	}
}

static int
session_enqueue_cmd(struct session *s, const char *line)
{
	char	*copy;

	if (s->cmd_queue_n >= SESSION_CMD_QUEUE_MAX)
		return (0);

	if ((copy = strdup(line)) == NULL) {
		log_warn("session %u: strdup pipelined command", s->id);
		return (0);
	}

	s->cmd_queue[s->cmd_queue_n++] = copy;
	return (1);
}

void
session_dequeue_next(struct session *s)
{
	uint32_t	 i;
	char		*line;

	while (s->cmd_queue_n > 0 && !session_is_busy(s) &&
	    !s->cmd_gather) {
		line = s->cmd_queue[0];

		for (i = 1; i < s->cmd_queue_n; i++)
			s->cmd_queue[i - 1] = s->cmd_queue[i];
		s->cmd_queue_n--;

		session_run_cmd(s, line);
		free(line);
	}
}

static void
session_handle_line(struct session *s, char *line)
{
	const char	*errmsg;
	size_t		 i;
	char		*tag, *name, *args;
	int		 rc;

	rc = parse_command_line(line, &tag, &name, &args, &errmsg);
	if (tag == NULL) {
		log_debug("session %u: <<< (no tag)", s->id);
		session_reply(s, "*", "BAD", errmsg);
		return;
	}

	/* The arguments may hold a password. */
	if (name != NULL && (strcasecmp(name, "AUTHENTICATE") == 0 ||
	    strcasecmp(name, "LOGIN") == 0))
		log_debug("session %u: <<< %s %s <redacted>", s->id, tag,
		    name);
	else
		log_debug("session %u: <<< %s%s%s%s%s", s->id, tag,
		    name != NULL ? " " : "", name != NULL ? name : "",
		    args != NULL ? " " : "", args != NULL ? args : "");

	if (strlen(tag) >= IMAP_TAG_MAX) {
		session_reply(s, "*", "BAD", "tag too long");
		return;
	}
	/* An invalid tag is never echoed. */
	if (!tag_is_valid(tag)) {
		session_reply(s, "*", "BAD", "invalid tag");
		return;
	}
	if (rc == -1) {
		session_reply(s, tag, "BAD", errmsg);
		return;
	}
	if (name == NULL) {
		session_reply(s, tag, "BAD", "missing command");
		return;
	}

	for (i = 0; i < nitems(imap_cmds); i++) {
		if (strcasecmp(name, imap_cmds[i].name) == 0)
			break;
	}
	if (i == nitems(imap_cmds)) {
		session_reply(s, tag, "BAD", "unknown command");
		return;
	}
	if (!(imap_cmds[i].states & (1U << s->state))) {
		/* BAD or NO are both allowed here. */
		session_reply(s, tag, "BAD",
		    "command not permitted in this state");
		return;
	}
	session_cmd_clear(s);
	strlcpy(s->cmd.pending_tag, tag, sizeof(s->cmd.pending_tag));
	imap_cmds[i].handler(s, tag, args);
}

static void
session_cmd_clear(struct session *s)
{
	struct session_cmd	*c = &s->cmd;

	free(c->pending_header_buf);
	if (c->pending_body_fd != -1)
		close(c->pending_body_fd);
	free(c->pending_envelope_buf);
	free(c->pending_bodystructure_buf);
	free(c->search_matches);
	free(c->vanished_ranges);
	free(c->qresync_fetches);
	free(c->copy_src_uids);
	free(c->copy_dest_uids);
	free(c->move_expunged);
	free(c->store_modified);
	memset(c, 0, sizeof(*c));
	c->pending_body_fd = -1;
}

static void
listener_dispatch_auth(int fd, short event, void *arg)
{
	struct imsg_auth_result	 res;
	struct session		*s;
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	int			 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1)
			fatal("imsgbuf_write");
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0) {
			/* The auth worker exits after a grant. */
			if (auth_granted)
				log_debug("auth-worker exited after the login");
			else
				log_warnx("auth-worker closed channel");
			event_del(&iev->ev);
			close(iev->ibuf.fd);
			imsgbuf_clear(&iev->ibuf);
			iev->ibuf.fd = -1;
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_AUTH_RESULT:
			s = &sess;

			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1) {
				log_warnx("bad IMSG_AUTH_RESULT");
				break;
			}
			if (res.session_id != s->id) {
				log_debug("IMSG_AUTH_RESULT for session %u, "
				    "not ours", res.session_id);
				break;
			}
			if (!res.ok) {
				s->state = SESSION_NOT_AUTH;
				/* Clear it, so the close line names no user. */
				explicit_bzero(s->user, sizeof(s->user));
				session_reply(s, s->cmd.pending_tag, "NO",
				    "[AUTHENTICATIONFAILED] authentication "
				    "failed");
				break;
			}

			auth_granted = 1;
			setproctitle("session %u [authenticated]", s->id);
			if (s->state != SESSION_AUTHENTICATING) {
				log_debug("session %u: auth result after the "
				    "store peer", s->id);
				break;
			}
			s->state = SESSION_STORE_PENDING;
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
listener_dispatch_parent(int fd, short event, void *arg)
{
	struct imsg_store_fork	 fail;
	struct session		*s;
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	uint32_t		 sess_id;
	int			 n, store_fd;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1)
			fatal("imsgbuf_write");
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0) {
			/* The parent is stopping us, so end the session. */
			log_debug("listener-worker: parent closed "
			    "channel, shutting down");
			session_teardown(&sess, "shutdown");
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_STORE_FORK:
			s = &sess;

			if (imsg_get_data(&imsg, &fail, sizeof(fail)) == -1) {
				log_warnx("bad IMSG_STORE_FORK reply");
				break;
			}
			if (fail.session_id != s->id)
				break;
			/* Send BYE before closing. */
			if (fail.limit) {
				session_untagged(s, "BYE [LIMIT] too many "
				    "sessions for this account");
				session_reply(s, s->cmd.pending_tag, "NO",
				    "[LIMIT] too many sessions for this "
				    "account");
				session_teardown(s, "limit-exceeded");
			} else {
				session_untagged(s, "BYE [UNAVAILABLE] "
				    "mailbox store unavailable");
				session_reply(s, s->cmd.pending_tag, "NO",
				    "[UNAVAILABLE] authentication "
				    "succeeded but mailbox store unavailable");
				session_teardown(s, "io-error");
			}
			break;
		case IMSG_SETUP_PEER:
			s = &sess;

			sess_id = imsg_get_id(&imsg);
			store_fd = imsg_get_fd(&imsg);
			if (store_fd == -1) {
				log_warnx("IMSG_SETUP_PEER (store) carried "
				    "no fd");
				break;
			}
			if (sess_id != s->id) {
				log_warnx("IMSG_SETUP_PEER (store) for "
				    "session %u, not ours", sess_id);
				close(store_fd);
				break;
			}
			s->store_iev = calloc(1, sizeof(*s->store_iev));
			if (s->store_iev == NULL) {
				log_warn("calloc");
				close(store_fd);
				break;
			}
			imsgev_init(s->store_iev, store_fd,
			    session_store_dispatch, s);
			s->state = SESSION_AUTHENTICATED;
			session_login_grace_disarm(s);
			log_debug("session %u: store peer wired", sess_id);
			session_reply(s, s->cmd.pending_tag, "OK", "logged in");
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
 * Reason is a fixed token, never attacker text.
 */
__dead void
session_teardown(struct session *s, const char *reason)
{
	struct timespec	 now;
	const char	*who = "-";
	long long	 dur = -1;
	int		 ret;

	if (s->store_iev != NULL) {
		if (imsg_compose(&s->store_iev->ibuf, IMSG_STORE_SHUTDOWN,
		    0, 0, -1, NULL, 0) == -1)
			log_warn("session %u: imsg_compose "
			    "IMSG_STORE_SHUTDOWN", s->id);
		else if (imsgbuf_flush(&s->store_iev->ibuf) == -1)
			log_warn("session %u: imsgbuf_flush "
			    "IMSG_STORE_SHUTDOWN", s->id);
		event_del(&s->store_iev->ev);
		close(s->store_iev->ibuf.fd);
		free(s->store_iev);
	}

	session_idle_poll_disarm(s);
	session_login_grace_disarm(s);

	if (s->client_ev_added)
		event_del(&s->client_ev);

	if (s->tls_ctx != NULL) {
		ret = tls_close(s->tls_ctx);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
			close(s->client_fd);
		/* A missing close_notify is routine, so debug only. */
		else if (ret != 0)
			log_debug("session %u: tls_close: %s", s->id,
			    tls_error(s->tls_ctx));
		tls_free(s->tls_ctx);
	} else {
		close(s->client_fd);
	}

	session_cmd_clear(s);

	while (s->cmd_queue_n > 0)
		free(s->cmd_queue[--s->cmd_queue_n]);

	if (clock_gettime(CLOCK_MONOTONIC, &now) != -1 &&
	    s->connected_at.tv_sec != 0)
		dur = (long long)(now.tv_sec - s->connected_at.tv_sec);
	/* The user is shown only after authenticating. */
	if (s->user[0] != '\0' && s->state != SESSION_AUTHENTICATING)
		who = s->user;
	/* Here tls is the final state, unlike at connect. */
	log_info("session %u: closed peer=%.200s user=%.64s reason=%s tls=%s "
	    "duration=%lld", s->id, s->remote_addr, who, reason,
	    s->tls_active ? "yes" : "no", dur);

	/* The inbuf may hold a base64 SASL response. */
	explicit_bzero(s, sizeof(*s));

	log_debug("listener-worker: session closed, exiting");
	exit(0);
}
