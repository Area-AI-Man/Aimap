#include "utf8.h"

int
utf8_mailbox_ok(const char *name)
{
	const unsigned char	*p = (const unsigned char *)name;
	unsigned int		need, lo, hi, i;

	while (*p != '\0') {
		if (p[0] < 0x80) {
			p++;
			continue;
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

		if (p[1] < lo || p[1] > hi)
			return (0);
		for (i = 2; i <= need; i++)
			if (p[i] < 0x80 || p[i] > 0xbf)
				return (0);

		/* No C1 controls. */
		if (p[0] == 0xc2 && p[1] <= 0x9f)
			return (0);

		/* No byte order mark anywhere. */
		if (p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf)
			return (0);

		p += need + 1;
	}

	return (1);
}
