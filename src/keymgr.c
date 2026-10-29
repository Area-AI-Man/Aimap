/*
 * Copyright (c) 2015 Joel Sing <jsing@openbsd.org>
 * Copyright (c) 2015 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "aimap.h"
#include "log.h"

struct keymgr_peer {
	uint32_t		 session_id;
	struct imsgev		 iev;
	TAILQ_ENTRY(keymgr_peer) entry;
};
static TAILQ_HEAD(, keymgr_peer)	 keymgr_peers =
	    TAILQ_HEAD_INITIALIZER(keymgr_peers);

static struct imsgev	 iev_parent;

static char	*reload_cert, *reload_key;
static size_t	 reload_cert_len, reload_cert_got;
static size_t	 reload_key_len, reload_key_got;
static int	 reload_got_cert, reload_got_key;

static EVP_PKEY	*keymgr_pkey;
static char	 keymgr_hash[KEYMGR_HASH_MAX];

/* Set once the first pair arrives, even if rejected. */
static int	 keymgr_got_init;

static void	 keymgr_key_free(void);
static int	 keymgr_load(const char *, size_t, const char *, size_t);
static void	 keymgr_try_reload(void);
static int	 keymgr_pubkey_hash(X509 *, char *, size_t);
static void	 keymgr_dispatch_listener(int, short, void *);
static void	 keymgr_peer_teardown(struct keymgr_peer *);
static void	 keymgr_dispatch_parent(int, short, void *);
static void	 keymgr_handle_rsa(struct imsgev *, struct imsg *, uint32_t,
		    uint32_t);
static void	 keymgr_handle_ecdsa(struct imsgev *, struct imsg *,
		    uint32_t);
static void	 keymgr_reply(struct imsgev *, uint32_t, uint32_t, int,
		    const void *, size_t);
static int	 keymgr_recv_trailing(struct ibuf *, uint32_t,
		    unsigned char *, size_t);

__dead void
keymgr_main(void)
{
	struct imsgbuf	 ibuf3;
	struct passwd	*pw;
	struct imsg	 imsg;
	size_t		 cert_len = 0, cert_got = 0;
	size_t		 key_len = 0, key_got = 0;
	char		*cert = NULL, *key = NULL;
	int		 n;
	int		 got_cert = 0, got_key = 0;

	imsgev_ibuf_init(&ibuf3, 3);

	/* The key is ready before any peer can ask. */
	while (!got_cert || !got_key) {
		if ((n = imsgbuf_get(&ibuf3, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0) {
			if ((n = imsgbuf_read(&ibuf3)) == -1)
				fatal("imsgbuf_read");
			if (n == 0)
				fatalx("parent closed channel "
				    "before INIT");
			continue;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_TLS_CERT:
			if (recv_chunk(&imsg, &cert, &cert_len, &cert_got,
			    "IMSG_TLS_CERT") == -1 || cert_got == cert_len)
				got_cert = 1;
			break;
		case IMSG_KEYMGR_INIT:
			if (recv_chunk(&imsg, &key, &key_len, &key_got,
			    "IMSG_KEYMGR_INIT") == -1 || key_got == key_len)
				got_key = 1;
			break;
		default:
			log_debug("keymgr boot: unhandled %d",
			    imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}

	if (cert_len == 0 || key_len == 0)
		log_warnx("no usable TLS cert/key, handshakes fail until a "
		    "reload");
	else if (keymgr_load(cert, cert_len, key, key_len) == -1)
		log_warnx("TLS cert/key not loaded, handshakes fail until a "
		    "reload");
	freezero(key, key_len);
	free(cert);
	keymgr_got_init = 1;

	if ((pw = getpwnam(AIMAP_USER)) == NULL)
		fatalx("unknown user %s", AIMAP_USER);

	/* The key came by imsg, nothing else is read. */
	if (chroot(PATH_CHROOT) == -1)
		fatal("chroot %s", PATH_CHROOT);
	if (chdir("/") == -1)
		fatal("chdir /");

	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("cannot drop privileges to _aimap");

	setproctitle("keymgr");

	setup_recv_done_and_ack(&ibuf3);

	event_init();

	imsgev_init_from_ibuf(&iev_parent, &ibuf3, keymgr_dispatch_parent,
	    NULL);

	/* Peers arrive as descriptors, none are sent. */
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
}

/*
 * The hash must match libtls's tag for the key.
 */
static int
keymgr_pubkey_hash(X509 *cert, char *hash, size_t hashlen)
{
	static const char	hex[] = "0123456789abcdef";
	unsigned char		digest[EVP_MAX_MD_SIZE];
	unsigned int		dlen, i;
	size_t			off;

	if (X509_pubkey_digest(cert, EVP_sha256(), digest, &dlen) != 1)
		return (-1);
	if (hashlen < 2 * (size_t)dlen + sizeof("SHA256:"))
		return (-1);

	off = strlcpy(hash, "SHA256:", hashlen);
	for (i = 0; i < dlen; i++) {
		hash[off++] = hex[(digest[i] >> 4) & 0x0f];
		hash[off++] = hex[digest[i] & 0x0f];
	}
	hash[off] = '\0';
	return (0);
}

static void
keymgr_key_free(void)
{
	if (keymgr_pkey != NULL) {
		EVP_PKEY_free(keymgr_pkey);
		keymgr_pkey = NULL;
	}
}

/*
 * A failed reload keeps the last good key.
 */
static int
keymgr_load(const char *cert_buf, size_t cert_len, const char *key_buf,
    size_t key_len)
{
	EVP_PKEY	*pkey = NULL;
	X509		*cert = NULL;
	char		 hash[KEYMGR_HASH_MAX];
	BIO		*cert_bio = NULL, *key_bio = NULL;
	int		 rc = -1;

	if (cert_len == 0 || key_len == 0) {
		log_warnx("empty cert or key, not (re)loading");
		return (-1);
	}

	if ((cert_bio = BIO_new_mem_buf(cert_buf, (int)cert_len)) == NULL) {
		log_warnx("BIO_new_mem_buf (cert) failed");
		goto fail;
	}
	if ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) == NULL) {
		log_warnx("PEM_read_bio_X509 failed");
		goto fail;
	}
	if (keymgr_pubkey_hash(cert, hash, sizeof(hash)) == -1) {
		log_warnx("could not hash certificate pubkey");
		goto fail;
	}

	if ((key_bio = BIO_new_mem_buf(key_buf, (int)key_len)) == NULL) {
		log_warnx("BIO_new_mem_buf (key) failed");
		goto fail;
	}
	if ((pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL))
	    == NULL) {
		log_warnx("PEM_read_bio_PrivateKey failed");
		goto fail;
	}

	/* Each may parse and still not match the other. */
	if (X509_check_private_key(cert, pkey) != 1) {
		log_warnx("certificate and private key do not match, not "
		    "(re)loading");
		goto fail;
	}

	/* Only now, with both parsed, touch the live state. */
	keymgr_key_free();
	keymgr_pkey = pkey;
	pkey = NULL;
	(void)strlcpy(keymgr_hash, hash, sizeof(keymgr_hash));

	log_info("TLS key loaded (%s)", keymgr_hash);
	rc = 0;

fail:
	BIO_free(cert_bio);
	BIO_free(key_bio);
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return (rc);
}

static void
keymgr_try_reload(void)
{
	if (!reload_got_cert || !reload_got_key)
		return;

	if (keymgr_load(reload_cert, reload_cert_len, reload_key,
	    reload_key_len) == -1)
		log_warnx("SIGHUP: keeping the previous key");
	freezero(reload_key, reload_key_len);
	free(reload_cert);
	reload_key = reload_cert = NULL;
	reload_key_len = reload_key_got = 0;
	reload_cert_len = reload_cert_got = 0;
	reload_got_cert = reload_got_key = 0;
}

static void
keymgr_dispatch_parent(int fd, short event, void *arg)
{
	struct keymgr_peer	*kp;
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	uint32_t		 sess_id;
	int			 n, peer_fd, flags;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1)
			fatal("imsgbuf_write");
	}
	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("imsgbuf_read");
		if (n == 0) {
			log_warnx("parent closed channel, exiting");
			keymgr_key_free();
			exit(0);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_KEYMGR_SHUTDOWN:
			log_debug("asked to shut down, exiting");
			imsg_free(&imsg);
			keymgr_key_free();
			exit(0);
		case IMSG_SETUP_PEER:
			sess_id = imsg_get_id(&imsg);
			peer_fd = imsg_get_fd(&imsg);
			if (peer_fd == -1) {
				log_warnx("IMSG_SETUP_PEER carried no fd");
				break;
			}
			/* A stalled listener must not stall keymgr. */
			if ((flags = fcntl(peer_fd, F_GETFL)) == -1 ||
			    fcntl(peer_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
				log_warn("session %u: fcntl O_NONBLOCK",
				    sess_id);
				close(peer_fd);
				break;
			}
			if ((kp = calloc(1, sizeof(*kp))) == NULL) {
				log_warn("calloc");
				close(peer_fd);
				break;
			}
			kp->session_id = sess_id;
			imsgev_init(&kp->iev, peer_fd, keymgr_dispatch_listener,
			    kp);
			TAILQ_INSERT_TAIL(&keymgr_peers, kp, entry);
			log_debug("session %u: listener peer wired", sess_id);
			break;
		case IMSG_TLS_CERT:
			if (recv_chunk(&imsg, &reload_cert, &reload_cert_len,
			    &reload_cert_got, "IMSG_TLS_CERT") == -1 ||
			    reload_cert_got == reload_cert_len) {
				reload_got_cert = 1;
				keymgr_try_reload();
			}
			break;
		case IMSG_KEYMGR_INIT:
			if (recv_chunk(&imsg, &reload_key, &reload_key_len,
			    &reload_key_got, "IMSG_KEYMGR_INIT") == -1 ||
			    reload_key_got == reload_key_len) {
				reload_got_key = 1;
				keymgr_try_reload();
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
keymgr_dispatch_listener(int fd, short event, void *arg)
{
	struct keymgr_peer	*kp = arg;
	struct imsgev		*iev = &kp->iev;
	struct imsg		 imsg;
	int			 n;

	/* A write failure drops this peer only. */
	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			log_warn("session %u: write error on listener "
			    "channel, dropping this peer", kp->session_id);
			keymgr_peer_teardown(kp);
			return;
		}
	}
	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1) {
			log_warn("session %u: read error on listener "
			    "channel, dropping this peer", kp->session_id);
			keymgr_peer_teardown(kp);
			return;
		}
		if (n == 0) {
			log_debug("session %u: listener closed channel",
			    kp->session_id);
			keymgr_peer_teardown(kp);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_KEYMGR_RSA_PRIVENC:
		case IMSG_KEYMGR_RSA_PRIVDEC:
			keymgr_handle_rsa(iev, &imsg, imsg_get_type(&imsg),
			    imsg_get_id(&imsg));
			break;
		case IMSG_KEYMGR_ECDSA_SIGN:
			keymgr_handle_ecdsa(iev, &imsg, imsg_get_id(&imsg));
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
keymgr_peer_teardown(struct keymgr_peer *kp)
{
	event_del(&kp->iev.ev);
	close(kp->iev.ibuf.fd);
	imsgbuf_clear(&kp->iev.ibuf);
	TAILQ_REMOVE(&keymgr_peers, kp, entry);
	free(kp);
}

static int
keymgr_recv_trailing(struct ibuf *ibuf, uint32_t len, unsigned char *buf,
    size_t bufsize)
{
	size_t	 bodylen;

	bodylen = ibuf_size(ibuf);
	if (len > bufsize || bodylen != (size_t)len) {
		log_warnx("trailing data length mismatch (header %u, imsg "
		    "%zu, buffer %zu)", len, bodylen, bufsize);
		return (-1);
	}
	if (bodylen == 0)
		return (0);
	if (ibuf_get(ibuf, buf, bodylen) == -1) {
		log_warnx("bad trailing data");
		return (-1);
	}
	return (0);
}

/*
 * Reply with the request's type, paired by its id.
 */
static void
keymgr_reply(struct imsgev *iev, uint32_t type, uint32_t id, int ok,
    const void *to, size_t tolen)
{
	struct imsg_keymgr_sign_reply	 rep;
	struct iovec			 iov[2];

	if (ok && tolen > KEYMGR_DATA_MAX) {
		log_warnx("%s: %zu bytes over KEYMGR_DATA_MAX %d", __func__,
		    tolen, KEYMGR_DATA_MAX);
		ok = 0;
	}

	memset(&rep, 0, sizeof(rep));
	rep.ok = ok;
	rep.tolen = ok ? (uint32_t)tolen : 0;

	iov[0].iov_base = &rep;
	iov[0].iov_len = sizeof(rep);
	iov[1].iov_base = (void *)to;
	iov[1].iov_len = rep.tolen;
	if (imsg_composev(&iev->ibuf, type, id, 0, -1, iov,
	    rep.tolen > 0 ? 2 : 1) == -1)
		log_warn("imsg_composev reply");
}

/*
 * RSA operations for listeners, which lack the key.
 */
static void
keymgr_handle_rsa(struct imsgev *iev, struct imsg *imsg, uint32_t type,
    uint32_t id)
{
	struct imsg_keymgr_sign_request	 req;
	unsigned char			 from[KEYMGR_DATA_MAX];
	unsigned char			 to[KEYMGR_DATA_MAX];
	struct ibuf			 ibuf;
	const char			*opname;
	RSA				*rsa = NULL;
	int				 ret = 0;

	opname = type == IMSG_KEYMGR_RSA_PRIVENC ? "RSA_PRIVENC" :
	    "RSA_PRIVDEC";
	if (imsg_get_ibuf(imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &req, sizeof(req)) == -1) {
		log_warnx("bad %s request (header)", opname);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}
	/* The received hash is not NUL-terminated. */
	req.hash[sizeof(req.hash) - 1] = '\0';

	if (keymgr_recv_trailing(&ibuf, req.fromlen, from,
	    sizeof(from)) == -1) {
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}

	if (!keymgr_got_init) {
		log_warnx("%s before IMSG_KEYMGR_INIT", opname);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}
	if (keymgr_pkey == NULL || strcmp(req.hash, keymgr_hash) != 0) {
		log_warnx("%s: unknown key hash", opname);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}

	if ((rsa = EVP_PKEY_get1_RSA(keymgr_pkey)) == NULL) {
		log_warnx("%s: loaded key is not RSA", opname);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}
	if ((size_t)RSA_size(rsa) > sizeof(to)) {
		log_warnx("%s: RSA key too large (%d > %zu)",
		    opname, RSA_size(rsa), sizeof(to));
		RSA_free(rsa);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		return;
	}

	if (type == IMSG_KEYMGR_RSA_PRIVENC)
		ret = RSA_private_encrypt((int)req.fromlen, from, to, rsa,
		    (int)req.padding);
	else
		ret = RSA_private_decrypt((int)req.fromlen, from, to, rsa,
		    (int)req.padding);
	RSA_free(rsa);

	if (ret <= 0) {
		log_warnx("%s failed", opname);
		keymgr_reply(iev, type, id, 0, NULL, 0);
		explicit_bzero(to, sizeof(to));
		return;
	}
	keymgr_reply(iev, type, id, 1, to, (size_t)ret);
	/* It held the decrypted premaster secret. */
	explicit_bzero(to, sizeof(to));
}

static void
keymgr_handle_ecdsa(struct imsgev *iev, struct imsg *imsg, uint32_t id)
{
	struct imsg_keymgr_sign_request	 req;
	unsigned char			 dgst[KEYMGR_DATA_MAX];
	unsigned char			 sig[KEYMGR_DATA_MAX];
	unsigned int			 siglen;
	struct ibuf			 ibuf;
	EC_KEY				*ec = NULL;
	int				 ret;

	if (imsg_get_ibuf(imsg, &ibuf) == -1 ||
	    ibuf_get(&ibuf, &req, sizeof(req)) == -1) {
		log_warnx("bad ECDSA_SIGN request (header)");
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}
	req.hash[sizeof(req.hash) - 1] = '\0';

	if (keymgr_recv_trailing(&ibuf, req.fromlen, dgst,
	    sizeof(dgst)) == -1) {
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}

	if (!keymgr_got_init) {
		log_warnx("ECDSA_SIGN before IMSG_KEYMGR_INIT");
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}
	if (keymgr_pkey == NULL || strcmp(req.hash, keymgr_hash) != 0) {
		log_warnx("ECDSA_SIGN: unknown key hash");
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}

	if ((ec = EVP_PKEY_get1_EC_KEY(keymgr_pkey)) == NULL) {
		log_warnx("ECDSA_SIGN: loaded key is not EC");
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}
	if ((size_t)ECDSA_size(ec) > sizeof(sig)) {
		log_warnx("ECDSA_SIGN: signature too large "
		    "(%d > %zu)", ECDSA_size(ec), sizeof(sig));
		EC_KEY_free(ec);
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		return;
	}

	siglen = (unsigned int)sizeof(sig);
	ret = ECDSA_sign(0, dgst, (int)req.fromlen, sig, &siglen, ec);
	EC_KEY_free(ec);

	if (ret != 1) {
		log_warnx("ECDSA_sign failed");
		keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 0, NULL, 0);
		explicit_bzero(sig, sizeof(sig));
		return;
	}
	keymgr_reply(iev, IMSG_KEYMGR_ECDSA_SIGN, id, 1, sig, siglen);
	explicit_bzero(sig, sizeof(sig));
}
