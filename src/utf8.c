#include <string.h>

#include "utf8.h"

/*
 * Set *lenp to the length of the UTF-8 character at p and return 1, or
 * return 0.  The caller passes len of at least 1.
 */
int
utf8_char(const unsigned char *p, size_t len, size_t *lenp)
{
	unsigned int	need, lo, hi, i;

	if (p[0] < 0x80) {
		*lenp = 1;
		return (1);
	}

	/* RFC 3629 section 4, one branch per lead byte. */
	if (p[0] >= 0xc2 && p[0] <= 0xdf) {
		need = 1;
		lo = 0x80;
		hi = 0xbf;
	} else if (p[0] == 0xe0) {
		need = 2;
		lo = 0xa0;	/* Not overlong. */
		hi = 0xbf;
	} else if ((p[0] >= 0xe1 && p[0] <= 0xec) || p[0] == 0xee ||
	    p[0] == 0xef) {
		need = 2;
		lo = 0x80;
		hi = 0xbf;
	} else if (p[0] == 0xed) {
		need = 2;
		lo = 0x80;
		hi = 0x9f;	/* No surrogates. */
	} else if (p[0] == 0xf0) {
		need = 3;
		lo = 0x90;	/* Not overlong. */
		hi = 0xbf;
	} else if (p[0] >= 0xf1 && p[0] <= 0xf3) {
		need = 3;
		lo = 0x80;
		hi = 0xbf;
	} else if (p[0] == 0xf4) {
		need = 3;
		lo = 0x80;
		hi = 0x8f;	/* At most U+10FFFF. */
	} else {
		return (0);
	}

	if (len <= need)
		return (0);
	if (p[1] < lo || p[1] > hi)
		return (0);
	for (i = 2; i <= need; i++)
		if (p[i] < 0x80 || p[i] > 0xbf)
			return (0);
	*lenp = need + 1;
	return (1);
}

int
utf8_mailbox_ok(const char *name)
{
	const unsigned char	*p = (const unsigned char *)name;
	size_t			left, n;

	left = strlen(name);
	while (left > 0) {
		if (!utf8_char(p, left, &n))
			return (0);

		/* No C1 controls. */
		if (p[0] == 0xc2 && p[1] <= 0x9f)
			return (0);

		/* No byte order mark anywhere. */
		if (p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf)
			return (0);

		p += n;
		left -= n;
	}

	return (1);
}
