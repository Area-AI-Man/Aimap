#include <sys/types.h>

#include <netinet/in.h>

#include <errno.h>
#include <imsg.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"

#define CAPABILITY_PRE_TLS	"IMAP4rev2 STARTTLS LOGINDISABLED "	\
				"ID CONDSTORE QRESYNC ESEARCH IDLE "	\
				"UIDPLUS LITERAL- MOVE"
#define CAPABILITY_POST_TLS	"IMAP4rev2 AUTH=PLAIN LOGINDISABLED "	\
				"ID CONDSTORE QRESYNC ESEARCH IDLE "	\
				"UIDPLUS LITERAL- MOVE SASL-IR"

static void	 session_set_user(struct session *, const unsigned char *,
		    size_t);
static void	 sasl_plain_finish(struct session *, const char *, const char *,
		    int);

void
cmd_capability(struct session *s, const char *tag, char *args)
{
	session_untagged(s, s->tls_active ?
	    "CAPABILITY " CAPABILITY_POST_TLS :
	    "CAPABILITY " CAPABILITY_PRE_TLS);
	session_reply(s, tag, "OK", "CAPABILITY completed");
}

void
cmd_noop(struct session *s, const char *tag, char *args)
{
	/* In a mailbox, the reply waits for the refresh. */
	if (s->state != SESSION_SELECTED ||
	    session_request_idle_refresh(s) == -1) {
		session_reply(s, tag, "OK", "NOOP completed");
		return;
	}
	s->cmd.refresh_status = "OK";
	s->cmd.refresh_text = "NOOP completed";
}

void
cmd_logout(struct session *s, const char *tag, char *args)
{
	session_untagged(s, "BYE logging out");
	session_reply(s, tag, "OK", "LOGOUT completed");
	session_teardown(s, "logout");
}

void
cmd_id(struct session *s, const char *tag, char *args)
{
	const char	*errmsg;
	size_t		 len;
	char		*p = args, *lit;
	int		 inquote = 0;

	/* Only literals need reading, since the reply is NIL. */
	while (p != NULL && *p != '\0') {
		if (!inquote && *p == '{') {
			if (read_literal(&p, &lit, &len, &errmsg) == -1) {
				session_arg_error(s, tag, errmsg);
				return;
			}
			continue;
		}
		if (inquote && *p == '\\' && p[1] != '\0')
			p++;
		else if (*p == '"')
			inquote = !inquote;
		p++;
	}
	log_debug("session %u: ID params: %s", s->id,
	    args != NULL ? args : "(none)");
	session_untagged(s, "ID NIL");
	session_reply(s, tag, "OK", "ID completed");
}

void
cmd_login(struct session *s, const char *tag, char *args)
{
	session_reply(s, tag, "NO",
	    "LOGIN not supported, use AUTHENTICATE PLAIN");
}

void
cmd_starttls(struct session *s, const char *tag, char *args)
{
	if (args != NULL) {
		session_reply(s, tag, "BAD", "STARTTLS takes no arguments");
		return;
	}
	if (s->tls_active) {
		session_reply(s, tag, "BAD", "TLS already active");
		return;
	}
	if (listener_tls_ctx == NULL) {
		/* No certificate or key was loaded at startup. */
		session_reply(s, tag, "NO",
		    "[UNAVAILABLE] TLS negotiation unavailable");
		return;
	}

	/* The reply goes out before the handshake. */
	session_reply(s, tag, "OK", "begin TLS negotiation");

	/* Discard pipelined plaintext, against command injection. */
	s->inbuflen = 0;

	session_tls_start(s);
}

/* Three 255-octet fields, two NULs and a terminator. */
#define SASL_PLAIN_MAX	768

/*
 * Replace anything unprintable with "?", as auth_safe_name() does.
 */
static void
session_set_user(struct session *s, const unsigned char *in,
    size_t inlen)
{
	unsigned char	 c;
	size_t		 i;

	for (i = 0; i < inlen && i + 1 < sizeof(s->user); i++) {
		c = in[i];

		s->user[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
	}
	s->user[i] = '\0';
}

static void
sasl_plain_finish(struct session *s, const char *tag, const char *b64,
    int allow_empty_equals)
{
	unsigned char			 raw[SASL_PLAIN_MAX];
	unsigned char			*authcid, *nul;
	const unsigned char		*passwd;
	int				 rawlen;
	size_t				 off, authcidlen, passwdlen;
	struct imsg_auth_request	 req;

	if (allow_empty_equals && strcmp(b64, "=") == 0) {
		rawlen = 0;
	} else {
		rawlen = b64_pton(b64, raw, sizeof(raw));
		if (rawlen < 0) {
			session_reply(s, tag, "BAD", "invalid base64");
			return;
		}
	}

	if (rawlen == 0) {
		session_reply(s, tag, "BAD", "malformed SASL PLAIN message");
		explicit_bzero(raw, sizeof(raw));
		return;
	}

	nul = memchr(raw, '\0', (size_t)rawlen);
	if (nul == NULL) {
		session_reply(s, tag, "BAD", "malformed SASL PLAIN message");
		explicit_bzero(raw, sizeof(raw));
		return;
	}
	off = (size_t)(nul - raw) + 1;
	authcid = raw + off;
	nul = memchr(authcid, '\0', (size_t)rawlen - off);
	if (nul == NULL) {
		session_reply(s, tag, "BAD", "malformed SASL PLAIN message");
		explicit_bzero(raw, sizeof(raw));
		return;
	}
	authcidlen = (size_t)(nul - authcid);
	passwd = nul + 1;
	passwdlen = (size_t)rawlen - off - authcidlen - 1;

	/* An empty name or password is NO, not BAD. */
	if (authcidlen == 0 || passwdlen == 0) {
		session_reply(s, tag, "NO",
		    "[AUTHENTICATIONFAILED] authentication failed");
		explicit_bzero(raw, sizeof(raw));
		return;
	}
	/* The same NO, so length gives nothing away. */
	if (authcidlen >= AUTH_USERNAME_MAX || passwdlen >= AUTH_PASSWORD_MAX) {
		session_reply(s, tag, "NO",
		    "[AUTHENTICATIONFAILED] authentication failed");
		explicit_bzero(raw, sizeof(raw));
		return;
	}

	if (iev_auth.ibuf.fd == -1) {
		explicit_bzero(raw, sizeof(raw));
		session_reply(s, tag, "NO", "[UNAVAILABLE] authentication "
		    "temporarily unavailable");
		return;
	}

	memset(&req, 0, sizeof(req));
	req.session_id = s->id;
	memcpy(req.username, authcid, authcidlen);
	session_set_user(s, authcid, authcidlen);
	memcpy(req.password, passwd, passwdlen);
	explicit_bzero(raw, sizeof(raw));

	s->state = SESSION_AUTHENTICATING;

	if (imsg_compose(&iev_auth.ibuf, IMSG_AUTH_REQUEST, 0, 0, -1,
	    &req, sizeof(req)) == -1) {
		log_warn("session %u: imsg_compose IMSG_AUTH_REQUEST", s->id);
		explicit_bzero(&req, sizeof(req));
		explicit_bzero(s->user, sizeof(s->user));
		s->state = SESSION_NOT_AUTH;
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		return;
	}
	explicit_bzero(&req, sizeof(req));

}

void
session_handle_auth_continuation(struct session *s, const char *line)
{
	s->auth_cont = 0;

	/* A lone "*" cancels the exchange. */
	if (strcmp(line, "*") == 0) {
		session_reply(s, s->cmd.pending_tag, "BAD",
		    "AUTHENTICATE cancelled");
		return;
	}

	sasl_plain_finish(s, s->cmd.pending_tag, line, 0);
}

void
session_handle_idle_continuation(struct session *s, const char *line)
{
	int	done;

	s->idling = 0;
	s->idle_refresh_again = 0;
	session_idle_poll_disarm(s);

	done = strcasecmp(line, "DONE") == 0;
	s->cmd.refresh_status = done ? "OK" : "BAD";
	s->cmd.refresh_text = done ? "IDLE terminated" : "expected DONE";
	/* An EXPUNGE in flight must precede the reply. */
	if (!s->idle_refresh_pending) {
		session_reply(s, s->cmd.pending_tag, s->cmd.refresh_status,
		    s->cmd.refresh_text);
		s->cmd.refresh_status = NULL;
	}
}

void
cmd_authenticate(struct session *s, const char *tag, char *args)
{
	const char	*initial, *errmsg;
	char		*mech, *mechend, *p;

	if (args == NULL) {
		session_reply(s, tag, "BAD", "missing SASL mechanism name");
		return;
	}
	mech = args;
	for (p = mech; *p != '\0' && *p != ' '; p++)
		continue;
	if (*p == '\0') {
		initial = NULL;
	} else {
		mechend = p;
		if (read_sp(&p, &errmsg) == -1) {
			session_reply(s, tag, "BAD", errmsg);
			return;
		}
		*mechend = '\0';
		initial = p;
	}

	if (!s->tls_active) {
		session_reply(s, tag, "NO",
		    "[PRIVACYREQUIRED] plaintext authentication requires TLS");
		return;
	}

	if (strcasecmp(mech, "PLAIN") != 0) {
		session_reply(s, tag, "NO",
		    "authentication mechanism not available");
		return;
	}

	if (initial != NULL) {
		s->scrub_inbuf = 1;
		sasl_plain_finish(s, tag, initial, 1);
		return;
	}
	s->auth_cont = 1;
	session_write(s, "+ \r\n", 4);
}

void
cmd_enable(struct session *s, const char *tag, char *args)
{
	char		 buf[64], untagged[80];
	char		*tok;
	int		 want_condstore = 0, want_qresync = 0;
	int		 newly_condstore = 0, newly_qresync = 0;

	if (args == NULL) {
		session_reply(s, tag, "BAD",
		    "ENABLE requires at least one capability argument");
		return;
	}

	/* Check the whole list before enabling anything. */
	while ((tok = strsep(&args, " ")) != NULL) {
		if (*tok == '\0') {
			session_reply(s, tag, "BAD", "extra space");
			return;
		}
		if (strcasecmp(tok, "QRESYNC") == 0)
			want_qresync = 1;
		else if (strcasecmp(tok, "CONDSTORE") == 0)
			want_condstore = 1;
	}
	if (want_qresync && !s->qresync_enabled) {
		s->qresync_enabled = 1;
		newly_qresync = 1;
		if (!s->condstore_enabled)
			newly_condstore = 1;
	}
	if (want_condstore && !s->condstore_enabled)
		newly_condstore = 1;

	if (newly_condstore || newly_qresync)
		session_condstore_enable(s);

	/* Room for both names and a space. */
	buf[0] = '\0';
	if (newly_qresync)
		(void)strlcat(buf, "QRESYNC", sizeof(buf));
	if (newly_condstore) {
		if (buf[0] != '\0')
			(void)strlcat(buf, " ", sizeof(buf));
		(void)strlcat(buf, "CONDSTORE", sizeof(buf));
	}

	if (buf[0] != '\0') {
		snprintf(untagged, sizeof(untagged), "ENABLED %s", buf);
		session_untagged(s, untagged);
	} else
		session_untagged(s, "ENABLED");

	session_reply(s, tag, "OK", "ENABLE completed");
}
