/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef AIMAP_LOG_H
#define AIMAP_LOG_H

#include <sys/cdefs.h>
#include <stdarg.h>

void		 log_init(int, int);
void		 log_procinit(const char *);
void		 log_setverbose(int);
int		 log_getverbose(void);

void		 log_warn(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 log_warnx(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 log_info(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 log_debug(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 logit(int, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
void		 vlog(int, const char *, va_list);
__dead void	 fatal(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
__dead void	 fatalx(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));

#endif
