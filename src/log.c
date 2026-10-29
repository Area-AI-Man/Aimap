/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

static int	 log_foreground = 1;
static int	 log_verbose = 0;
static char	 log_procname[32] = "aimap";

static char	*log_escape_ctl(const char *);
static void	 log_write_line(const char *, size_t);
static void	 vfatalc(int, const char *, va_list);

static char *
log_escape_ctl(const char *s)
{
	const unsigned char	*p = (const unsigned char *)s;
	char			*out, *q;

	/* At worst two bytes out per byte in. */
	if ((out = malloc((2 * strlen(s)) + 1)) == NULL)
		return (NULL);

	for (q = out; *p != '\0'; p++) {
		if (p[0] == 0xc2 && p[1] >= 0x80 && p[1] <= 0x9f) {
			/* A C1 control, which some terminals still honour. */
			*q++ = 'M';
			*q++ = '-';
			*q++ = '^';
			*q++ = (char)((p[1] & 0x1f) + '@');
			p++;
		} else if (*p < 0x20) {
			*q++ = '^';
			*q++ = (char)(*p + '@');
		} else if (*p == 0x7f) {
			*q++ = '^';
			*q++ = '?';
		} else
			*q++ = (char)*p;
	}
	*q = '\0';
	return (out);
}

/*
 * Each line is one write(2), since processes share stderr.
 */
static void
log_write_line(const char *line, size_t len)
{
	ssize_t	 n;

	while (len > 0) {
		if ((n = write(STDERR_FILENO, line, len)) == -1) {
			if (errno == EINTR)
				continue;
			return;	/* Nowhere left to report it. */
		}
		line += n;
		len -= (size_t)n;
	}
}

void
log_init(int foreground, int verbose)
{
	log_foreground = foreground;
	log_verbose = verbose;

	/* The mail facility, so existing maillog rules apply. */
	if (!log_foreground)
		openlog("aimap", LOG_PID | LOG_NDELAY, LOG_MAIL);

	tzset();
}

void
log_procinit(const char *name)
{
	if (name != NULL)
		(void)strlcpy(log_procname, name, sizeof(log_procname));
}

void
log_setverbose(int v)
{
	log_verbose = v;
}

int
log_getverbose(void)
{
	return (log_verbose);
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	static const char	 dropped[] = "(message dropped: out of memory "
				    "while logging)\n";
	char			*msg, *safe, *line;
	int			 saved_errno = errno;

	if (log_foreground) {
		msg = NULL;
		safe = NULL;
		line = NULL;

		if (vasprintf(&msg, fmt, ap) == -1)
			msg = NULL;
		if (msg != NULL)
			safe = log_escape_ctl(msg);
		/* Escape first, or the newline would become ^J. */
		if (safe != NULL && asprintf(&line, "%s\n", safe) != -1) {
			log_write_line(line, strlen(line));
			free(line);
		} else
			log_write_line(dropped, sizeof(dropped) - 1);
		free(safe);
		free(msg);
	} else {
		/* The syslogd(8) daemon escapes control bytes itself. */
		vsyslog(pri, fmt, ap);
	}

	errno = saved_errno;
}

void
logit(int pri, const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
log_warn(const char *emsg, ...)
{
	va_list	 ap;
	char	*nfmt;
	int	 saved_errno = errno;

	if (emsg == NULL)
		logit(LOG_ERR, "%s", strerror(saved_errno));
	else {
		if (asprintf(&nfmt, "%s: %s", emsg,
		    strerror(saved_errno)) == -1) {
			va_start(ap, emsg);
			vlog(LOG_ERR, emsg, ap);
			va_end(ap);
			logit(LOG_ERR, "%s", strerror(saved_errno));
			errno = saved_errno;
			return;
		}
		va_start(ap, emsg);
		vlog(LOG_ERR, nfmt, ap);
		va_end(ap);
		free(nfmt);
	}

	errno = saved_errno;
}

void
log_warnx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_ERR, emsg, ap);
	va_end(ap);
}

void
log_info(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_INFO, emsg, ap);
	va_end(ap);
}

void
log_debug(const char *emsg, ...)
{
	va_list	 ap;

	if (log_verbose == 0)
		return;

	va_start(ap, emsg);
	vlog(LOG_DEBUG, emsg, ap);
	va_end(ap);
}

static void
vfatalc(int code, const char *emsg, va_list ap)
{
	static char	 s[BUFSIZ];
	const char	*sep;

	if (emsg != NULL) {
		(void)vsnprintf(s, sizeof(s), emsg, ap);
		sep = ": ";
	} else {
		s[0] = '\0';
		sep = "";
	}

	if (code)
		logit(LOG_CRIT, "fatal in %s: %s%s%s",
		    log_procname, s, sep, strerror(code));
	else
		logit(LOG_CRIT, "fatal in %s%s%s", log_procname, sep, s);
}

__dead void
fatal(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vfatalc(errno, emsg, ap);
	va_end(ap);
	exit(1);
}

__dead void
fatalx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vfatalc(0, emsg, ap);
	va_end(ap);
	exit(1);
}
