#include <sys/param.h>
#include <sys/stat.h>

#include <err.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"

static __dead void	 usage(void);

static const struct {
	const char		*name;
	enum aimap_proc_type	 type;
} proc_table[] = {
	{ "listener",	PROC_LISTENER },
	{ "auth",	PROC_AUTH },
	{ "store",	PROC_STORE },
	{ "keymgr",	PROC_KEYMGR },
	{ "parser",	PROC_PARSER },
};

const char *
proc_name(enum aimap_proc_type type)
{
	switch (type) {
	case PROC_PARENT:
		return ("parent");
	case PROC_LISTENER:
		return ("listener");
	case PROC_AUTH:
		return ("auth");
	case PROC_STORE:
		return ("store");
	case PROC_KEYMGR:
		return ("keymgr");
	case PROC_PARSER:
		return ("parser");
	default:
		return ("?");
	}
}

static __dead void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-dnVv] [-D macro=value] [-f file]\n",
	    getprogname());
	exit(1);
}

/*
 * An IMAP4rev2 server.  The parent starts each privilege-separated process
 * by executing this program again with -x and its role.
 */
int
main(int argc, char *argv[])
{
	int			 ch;
	int			 debug = 0, noaction = 0, verbose = 0;
	const char		*conffile = "/etc/aimap.conf";
	const char		*rolearg = NULL;
	enum aimap_proc_type	 role = PROC_PARENT;
	size_t			 i;
	struct aimap_config	 conf;
	struct stat		 sb;

	memset(&conf, 0, sizeof(conf));

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "D:df:nVvx:")) != -1) {
		switch (ch) {
		case 'V':
			printf("%s %s\n", getprogname(), AIMAP_VERSION);
			return (0);
		case 'D':
			if (cmdline_symset(optarg) == -1)
				fatalx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'x':
			rolearg = optarg;
			break;
		default:
			usage();
		}
	}

	if (rolearg != NULL) {
		for (i = 0; i < nitems(proc_table); i++) {
			if (strcmp(rolearg, proc_table[i].name) == 0) {
				role = proc_table[i].type;
				break;
			}
		}
		if (i == nitems(proc_table))
			usage();
	}

	/* Name the role before anything can log. */
	log_procinit(proc_name(role));
	log_init(debug, verbose);

	switch (role) {
	case PROC_PARENT:
		if (parse_config(conffile, &conf) == -1)
			fatalx("parse_config: %s", conffile);
		if (stat(PATH_CHROOT, &sb) == -1)
			fatal("%s", PATH_CHROOT);
		if (!S_ISDIR(sb.st_mode))
			fatalx("%s: not a directory", PATH_CHROOT);
		if (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0)
			fatalx("%s: not owned by root or writable by group "
			    "or other", PATH_CHROOT);
		if (noaction) {
			fprintf(stderr, "configuration OK\n");
			return (0);
		}
		if (geteuid() != 0)
			fatalx("parent must start as root (running as "
			    "uid %u)", (unsigned int)geteuid());
		if (getpwnam(AIMAP_USER) == NULL)
			fatalx("unknown user %s", AIMAP_USER);
		if (getpwnam(AIMAP_AUTH_USER) == NULL)
			fatalx("unknown user %s", AIMAP_AUTH_USER);
		parent_main(conffile, argc, argv, &conf, debug);
	case PROC_LISTENER:
		listener_main();
	case PROC_AUTH:
		auth_main();
	case PROC_STORE:
		store_main();
	case PROC_KEYMGR:
		keymgr_main();
	case PROC_PARSER:
		parser_main();
	}

	fatalx("unhandled role %d", role);
}
