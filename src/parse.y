/*
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 */

%{
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);
static void	 table_check(const char *);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

static struct aimap_config	*conf;
static int			 errors = 0;

static int			 have_cleartext = 0;
static int			 have_tls_listen = 0;

typedef struct {
	union {
		int64_t		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	LISTEN ON TLS PORT
%token	SPOOL CREDENTIALS USERBASE CERTIFICATE KEY
%token	APPEND ATTACHMENT MAX
%token	STARTUPS BEGIN RATE FULL PERSOURCE NONE
%token	IDLE POLL
%token	LOGIN GRACE
%token	LOCK TIMEOUT
%token	ACCOUNT SESSIONS
%token	CONNECTIONS
%token	INCLUDE
%token	ERROR
%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	opttls

%%

grammar		: /* Empty */
		| grammar '\n'
		| grammar include '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			/* An included file may hold the TLS key. */
			if ((nfile = pushfile($2, 1)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

varset		: STRING '=' STRING		{
			char *s = $1;

			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

opttls		: /* Empty */			{ $$ = 0; }
		| TLS				{ $$ = 1; }
		;

main		: LISTEN ON STRING opttls PORT NUMBER	{
			if ($6 < 1 || $6 > 65535) {
				yyerror("invalid port: %lld", $6);
				free($3);
				YYERROR;
			}

			/* The "*" means both IPv4-any and IPv6-any. */
			if (strcmp($3, "*") != 0) {
				struct in_addr	 ina;
				struct in6_addr	 ina6;

				if (inet_pton(AF_INET, $3, &ina) != 1 &&
				    inet_pton(AF_INET6, $3, &ina6) != 1) {
					yyerror("listen address \"%s\" is "
					    "not \"*\" or a literal IPv4/"
					    "IPv6 address", $3);
					free($3);
					YYERROR;
				}
			}

			if (have_cleartext || have_tls_listen) {
				if (strcmp(conf->listen_addr, $3) != 0) {
					yyerror("listen address \"%s\" does "
					    "not match earlier \"listen on "
					    "%s\", aimap binds both "
					    "listeners to the same address",
					    $3, conf->listen_addr);
					free($3);
					YYERROR;
				}
			} else if (strlcpy(conf->listen_addr, $3,
			    sizeof(conf->listen_addr)) >=
			    sizeof(conf->listen_addr)) {
				yyerror("listen address too long: %s", $3);
				free($3);
				YYERROR;
			}
			free($3);

			if ($4) {
				if (have_tls_listen) {
					yyerror("tls listener already "
					    "configured");
					YYERROR;
				}
				conf->port_implicit_tls = (uint16_t)$6;
				have_tls_listen = 1;
			} else {
				if (have_cleartext) {
					yyerror("cleartext listener already "
					    "configured");
					YYERROR;
				}
				conf->port_cleartext = (uint16_t)$6;
				have_cleartext = 1;
			}
		}
		| SPOOL STRING			{
			if (strlcpy(conf->spool_root, $2,
			    sizeof(conf->spool_root)) >=
			    sizeof(conf->spool_root)) {
				yyerror("spool path too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CREDENTIALS STRING		{
			if ($2[0] != '/') {
				yyerror("credentials path is not absolute: %s",
				    $2);
				free($2);
				YYERROR;
			}
			if (strlcpy(conf->cred_file, $2,
			    sizeof(conf->cred_file)) >=
			    sizeof(conf->cred_file)) {
				yyerror("credentials path too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| USERBASE STRING		{
			if ($2[0] != '/') {
				yyerror("userbase path is not absolute: %s",
				    $2);
				free($2);
				YYERROR;
			}
			if (strlcpy(conf->userbase_file, $2,
			    sizeof(conf->userbase_file)) >=
			    sizeof(conf->userbase_file)) {
				yyerror("userbase path too long: %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| TLS CERTIFICATE STRING	{
			if (strlcpy(conf->tls_cert_file, $3,
			    sizeof(conf->tls_cert_file)) >=
			    sizeof(conf->tls_cert_file)) {
				yyerror("tls certificate path too long: %s",
				    $3);
				free($3);
				YYERROR;
			}
			free($3);
		}
		| TLS KEY STRING		{
			if (strlcpy(conf->tls_key_file, $3,
			    sizeof(conf->tls_key_file)) >=
			    sizeof(conf->tls_key_file)) {
				yyerror("tls key path too long: %s", $3);
				free($3);
				YYERROR;
			}
			free($3);
		}
		| IDLE POLL NUMBER		{
			if ($3 < 0 || $3 > IDLE_POLL_MAX) {
				yyerror("idle poll out of range "
				    "(0 to disable, otherwise 1-%d "
				    "seconds): %lld", IDLE_POLL_MAX,
				    $3);
				YYERROR;
			}
			conf->idle_poll_secs = (uint32_t)$3;
		}
		| LOGIN GRACE NUMBER		{
			if ($3 < 0 || $3 > LOGIN_GRACE_MAX) {
				yyerror("login grace out of range "
				    "(0 to disable, otherwise 1-%d "
				    "seconds): %lld", LOGIN_GRACE_MAX,
				    $3);
				YYERROR;
			}
			conf->login_grace_secs = (uint32_t)$3;
		}
		| LOCK TIMEOUT NUMBER		{
			if ($3 < 0 || $3 > LOCK_TIMEOUT_MAX) {
				yyerror("lock timeout out of range "
				    "(0 to disable, otherwise 1-%d "
				    "seconds): %lld", LOCK_TIMEOUT_MAX,
				    $3);
				YYERROR;
			}
			conf->lock_timeout_secs = (uint32_t)$3;
		}
		| ACCOUNT SESSIONS NUMBER	{
			if ($3 < 1 || $3 > ACCOUNT_SESSIONS_MAX) {
				yyerror("account sessions out of range "
				    "(1-%d): %lld", ACCOUNT_SESSIONS_MAX,
				    $3);
				YYERROR;
			}
			conf->account_sessions = (uint32_t)$3;
		}
		| CONNECTIONS MAX NUMBER	{
			if ($3 < 1 || $3 > CONNECTIONS_MAX_MAX) {
				yyerror("connections max out of range "
				    "(1-%d): %lld", CONNECTIONS_MAX_MAX,
				    $3);
				YYERROR;
			}
			conf->connections_max = (uint32_t)$3;
		}
		| APPEND MAX NUMBER		{
			if ($3 < 1 || $3 > APPEND_MAX_MAX) {
				yyerror("append max out of range "
				    "(1-%d bytes): %lld", APPEND_MAX_MAX,
				    $3);
				YYERROR;
			}
			conf->append_max = (uint64_t)$3;
		}
		| ATTACHMENT MAX NUMBER		{
			if ($3 < BODYSTRUCTURE_MAX ||
			    $3 > BODYSTRUCTURE_READ_MAX) {
				yyerror("attachment max out of range "
				    "(%d-%d bytes): %lld", BODYSTRUCTURE_MAX,
				    BODYSTRUCTURE_READ_MAX, $3);
				YYERROR;
			}
			conf->bodystructure_read_max = (uint32_t)$3;
		}
		| STARTUPS PERSOURCE NUMBER	{
			if ($3 < 1 || $3 > STARTUPS_MAX) {
				yyerror("startups per-source out of range "
				    "(1-%d, or none): %lld", STARTUPS_MAX,
				    $3);
				YYERROR;
			}
			conf->max_startups_per_source = (uint32_t)$3;
		}
		| STARTUPS PERSOURCE NONE	{
			conf->max_startups_per_source = 0;
		}
		| STARTUPS BEGIN NUMBER RATE NUMBER FULL NUMBER {
			if ($3 < 0 || $3 > STARTUPS_MAX) {
				yyerror("startups begin out of range "
				    "(0-%d): %lld", STARTUPS_MAX,
				    $3);
				YYERROR;
			}
			if ($5 < 0 || $5 > 100) {
				yyerror("startups rate must be a percentage "
				    "(0-100): %lld", $5);
				YYERROR;
			}
			if ($7 < 0 || $7 > STARTUPS_MAX) {
				yyerror("startups full out of range "
				    "(0-%d): %lld", STARTUPS_MAX,
				    $7);
				YYERROR;
			}
			if ($7 < $3) {
				yyerror("startups full (%lld) must be >= "
				    "begin (%lld)", $7,
				    $3);
				YYERROR;
			}
			conf->max_startups_begin = (uint32_t)$3;
			conf->max_startups_rate = (uint32_t)$5;
			conf->max_startups_full = (uint32_t)$7;
		}
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* Keep this sorted, for bsearch(3). */
	static const struct keywords keywords[] = {
		{ "account",		ACCOUNT },
		{ "append",		APPEND },
		{ "attachment",		ATTACHMENT },
		{ "begin",		BEGIN },
		{ "certificate",	CERTIFICATE },
		{ "connections",	CONNECTIONS },
		{ "credentials",	CREDENTIALS },
		{ "full",		FULL },
		{ "grace",		GRACE },
		{ "idle",		IDLE },
		{ "include",		INCLUDE },
		{ "key",		KEY },
		{ "listen",		LISTEN },
		{ "lock",		LOCK },
		{ "login",		LOGIN },
		{ "max",		MAX },
		{ "none",		NONE },
		{ "on",			ON },
		{ "per-source",		PERSOURCE },
		{ "poll",		POLL },
		{ "port",		PORT },
		{ "rate",		RATE },
		{ "sessions",		SESSIONS },
		{ "spool",		SPOOL },
		{ "startups",		STARTUPS },
		{ "timeout",		TIMEOUT },
		{ "tls",		TLS },
		{ "userbase",		USERBASE },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time.  This gets line
		 * count right if last line in included file is
		 * syntactically invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "%s", __func__);
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		;

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			;
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "%s", __func__);
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

/*
 * Split a table(5) line into key and value, as smtpd(8) does.  A blank or
 * comment line has no key.
 */
int
table_line(char *line, char **key, char **val)
{
	char	*k, *v;
	size_t	 len;

	*key = *val = NULL;
	k = line;
	while (isspace((unsigned char)*k))
		k++;
	len = strlen(k);
	while (len > 0 && isspace((unsigned char)k[len - 1]))
		k[--len] = '\0';
	if (*k == '\0' || *k == '#')
		return (0);

	v = k + strcspn(k, " \t:");
	if (*v != '\0') {
		*v++ = '\0';
		v += strspn(v, " \t");
	}
	if (*v == '\0')
		return (-1);
	*key = k;
	*val = v;
	return (0);
}

/*
 * An early warning only.  The auth process and the parent decide at login.
 */
static void
table_check(const char *path)
{
	size_t	 linesize = 0;
	FILE	*fp;
	char	*line = NULL, *key, *val;
	int	 lineno = 0;

	if ((fp = fopen(path, "r")) == NULL) {
		if (geteuid() == 0)
			log_warn("%s", path);
		return;
	}
	while (getline(&line, &linesize, fp) != -1) {
		lineno++;
		if (table_line(line, &key, &val) == -1)
			log_warnx("%s:%d invalid map entry", path, lineno);
	}
	freezero(line, linesize);
	fclose(fp);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("%s", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("%s", __func__);
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn("%s", __func__);
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(const char *path, struct aimap_config *xconf)
{
	struct stat	 st;
	struct sym	*sym, *next;
	char		 cred[PATH_MAX], userbase[PATH_MAX];

	conf = xconf;
	memset(conf, 0, sizeof(*conf));

	(void)strlcpy(conf->listen_addr, "*", sizeof(conf->listen_addr));
	conf->port_cleartext = 143;
	conf->port_implicit_tls = 993;
	conf->idle_poll_secs = IDLE_POLL_DEFAULT;
	conf->login_grace_secs = LOGIN_GRACE_DEFAULT;
	conf->lock_timeout_secs = LOCK_TIMEOUT_DEFAULT;
	conf->account_sessions = ACCOUNT_SESSIONS_DEFAULT;
	conf->connections_max = CONNECTIONS_MAX_DEFAULT;
	(void)strlcpy(conf->spool_root, "/var/mail/aimap",
	    sizeof(conf->spool_root));
	(void)strlcpy(conf->cred_file, "/etc/aimap/credentials",
	    sizeof(conf->cred_file));
	(void)strlcpy(conf->userbase_file, "/etc/aimap/userbase",
	    sizeof(conf->userbase_file));
	(void)strlcpy(conf->tls_cert_file, "/etc/ssl/aimap.crt",
	    sizeof(conf->tls_cert_file));
	(void)strlcpy(conf->tls_key_file, "/etc/ssl/private/aimap.key",
	    sizeof(conf->tls_key_file));
	conf->bodystructure_read_max = BODYSTRUCTURE_READ_DEFAULT;
	conf->append_max = APPEND_MAX_DEFAULT;

	/* The MaxStartups default, 10:30:100. */
	conf->max_startups_begin = 10;
	conf->max_startups_rate = 30;
	conf->max_startups_full = 100;
	conf->max_startups_per_source = STARTUPS_PER_SOURCE_DEFAULT;

	have_cleartext = 0;
	have_tls_listen = 0;
	errors = 0;

	if ((file = pushfile(path, 1)) == NULL)
		return (-1);
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	if (have_cleartext || have_tls_listen) {
		if (!have_cleartext)
			conf->port_cleartext = 0;
		if (!have_tls_listen)
			conf->port_implicit_tls = 0;
	}

	/* Here, as the two may come in either order. */
	if (conf->append_max > conf->bodystructure_read_max) {
		log_warnx("%s: append max %llu exceeds attachment max %u",
		    path, (unsigned long long)conf->append_max,
		    conf->bodystructure_read_max);
		errors++;
	}

	/* The auth process splits only a canonical path. */
	if (realpath(conf->cred_file, cred) == NULL ||
	    stat(cred, &st) == -1) {
		log_warn("%s: credentials %s", path, conf->cred_file);
		errors++;
	} else if (!S_ISREG(st.st_mode)) {
		log_warnx("%s: credentials %s: not a regular file", path,
		    cred);
		errors++;
	} else {
		strlcpy(conf->cred_file, cred, sizeof(conf->cred_file));
		table_check(cred);
	}

	if (realpath(conf->userbase_file, userbase) == NULL ||
	    stat(userbase, &st) == -1) {
		log_warn("%s: userbase %s", path, conf->userbase_file);
		errors++;
	} else if (!S_ISREG(st.st_mode)) {
		log_warnx("%s: userbase %s: not a regular file", path,
		    userbase);
		errors++;
	} else {
		strlcpy(conf->userbase_file, userbase,
		    sizeof(conf->userbase_file));
		table_check(userbase);
	}

	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if (!sym->used)
			log_debug("%s: macro '%s' not used", __func__,
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors)
		return (-1);

	return (0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	 ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);
	sym = strndup(s, val - s);
	if (sym == NULL)
		fatal("%s: strndup", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}
