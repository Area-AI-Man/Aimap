#include <string.h>

#include "aimap.h"
#include "mboxname.h"
#include "utf8.h"

int
mailbox_name_is_inbox(const char *name)
{
	return (strcasecmp(name, "INBOX") == 0);
}

int
mailbox_name_syntax_ok(const char *name)
{
	unsigned char	c;
	size_t		i, len;

	len = strlen(name);
	if (len == 0 || len >= MBOX_NAME_MAX)
		return (0);

	if (!utf8_mailbox_ok(name))
		return (0);

	for (i = 0; i < len; i++) {
		c = (unsigned char)name[i];

		/* The hierarchy delimiter. */
		if (c == '/')
			return (0);
		if (c < 0x20 || c == 0x7f)
			return (0);
	}

	/* Maildir's own subdirectories, at the top of INBOX. */
	if (strcmp(name, "tmp") == 0 || strcmp(name, "new") == 0 ||
	    strcmp(name, "cur") == 0)
		return (0);

	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return (0);
	if (mailbox_name_reserved(name))
		return (0);

	return (1);
}

int
mailbox_name_reserved(const char *name)
{
	return (strcmp(name, STORE_INDEX_NAME) == 0 ||
	    strcmp(name, STORE_INDEX_TMP_NAME) == 0 ||
	    strcmp(name, STORE_INDEX_LOCK_NAME) == 0 ||
	    strcmp(name, STORE_UIDVALIDITY_NAME) == 0 ||
	    strcmp(name, STORE_SUBSCRIPTIONS_NAME) == 0 ||
	    strcmp(name, STORE_SUBSCRIPTIONS_TMP_NAME) == 0 ||
	    strcmp(name, STORE_SUBSCRIPTIONS_LOCK_NAME) == 0);
}
