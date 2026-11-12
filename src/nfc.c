#include <sys/param.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aimap.h"
#include "log.h"
#include "nfc.h"
#include "nfc_data.h"
#include "utf8.h"

#define HANGUL_LBASE	0x1100
#define HANGUL_VBASE	0x1161
#define HANGUL_TBASE	0x11A7
#define HANGUL_LCOUNT	19
#define HANGUL_VCOUNT	21
#define HANGUL_TCOUNT	28
#define HANGUL_NCOUNT	(HANGUL_VCOUNT * HANGUL_TCOUNT)

/*
 * A code point of one octet does not decompose.  One of two or more
 * octets decomposes to at most NFC_DECOMP_MAX code points, so a name fits.
 */
#define NFC_BUF_MAX	((size_t)MBOX_NAME_MAX * NFC_DECOMP_MAX)

static uint32_t	 utf8_decode(const unsigned char *, size_t);
static int	 ccc_cmp(const void *, const void *);
static int	 decomp_cmp(const void *, const void *);
static int	 comp_cmp(const void *, const void *);
static int	 range_cmp(const void *, const void *);
static uint8_t	 ccc_of(uint32_t);
static void	 push(uint32_t *, size_t *, uint32_t);
static void	 decompose(uint32_t, uint32_t *, size_t *);
static void	 reorder(uint32_t *, uint8_t *, size_t);
static int	 compose_pair(uint32_t, uint32_t, uint32_t *);
static size_t	 compose(uint32_t *, uint8_t *, size_t);

static uint32_t
utf8_decode(const unsigned char *p, size_t len)
{
	uint32_t	cp;
	size_t		i;

	if (len == 1)
		return (p[0]);
	cp = p[0] & (0xff >> (len + 1));
	for (i = 1; i < len; i++)
		cp = (cp << 6) | (p[i] & 0x3f);
	return (cp);
}

static int
ccc_cmp(const void *kp, const void *ep)
{
	const uint32_t		*k = kp;
	const struct nfc_ccc	*e = ep;

	if (*k < e->first)
		return (-1);
	if (*k > e->last)
		return (1);
	return (0);
}

static int
decomp_cmp(const void *kp, const void *ep)
{
	const uint32_t			*k = kp;
	const struct nfc_decomp		*e = ep;

	if (*k < e->cp)
		return (-1);
	if (*k > e->cp)
		return (1);
	return (0);
}

static int
comp_cmp(const void *kp, const void *ep)
{
	const struct nfc_comp	*k = kp;
	const struct nfc_comp	*e = ep;

	if (k->first != e->first)
		return (k->first < e->first ? -1 : 1);
	if (k->second != e->second)
		return (k->second < e->second ? -1 : 1);
	return (0);
}

static int
range_cmp(const void *kp, const void *ep)
{
	const uint32_t		*k = kp;
	const struct nfc_range	*e = ep;

	if (*k < e->first)
		return (-1);
	if (*k > e->last)
		return (1);
	return (0);
}

static uint8_t
ccc_of(uint32_t cp)
{
	const struct nfc_ccc	*e;

	e = bsearch(&cp, nfc_ccc, nitems(nfc_ccc), sizeof(nfc_ccc[0]),
	    ccc_cmp);
	return (e == NULL ? 0 : e->ccc);
}

static void
push(uint32_t *d, size_t *np, uint32_t cp)
{
	if (*np >= NFC_BUF_MAX)
		fatalx("nfc: decomposition too long");
	d[(*np)++] = cp;
}

static void
decompose(uint32_t cp, uint32_t *d, size_t *np)
{
	const struct nfc_decomp	*e;
	uint32_t		 s;
	size_t			 i;

	if (cp >= NFC_HANGUL_FIRST && cp <= NFC_HANGUL_LAST) {
		s = cp - NFC_HANGUL_FIRST;
		push(d, np, HANGUL_LBASE + s / HANGUL_NCOUNT);
		push(d, np, HANGUL_VBASE + s % HANGUL_NCOUNT / HANGUL_TCOUNT);
		if (s % HANGUL_TCOUNT != 0)
			push(d, np, HANGUL_TBASE + s % HANGUL_TCOUNT);
		return;
	}

	e = bsearch(&cp, nfc_decomp, nitems(nfc_decomp), sizeof(nfc_decomp[0]),
	    decomp_cmp);
	if (e == NULL) {
		push(d, np, cp);
		return;
	}
	for (i = 0; i < e->len; i++)
		push(d, np, e->to[i]);
}

static void
reorder(uint32_t *d, uint8_t *cc, size_t n)
{
	uint32_t	t;
	uint8_t		c;
	size_t		i, j;

	for (i = 1; i < n; i++) {
		for (j = i; j > 0 && cc[j] != 0 && cc[j - 1] > cc[j]; j--) {
			t = d[j];
			d[j] = d[j - 1];
			d[j - 1] = t;
			c = cc[j];
			cc[j] = cc[j - 1];
			cc[j - 1] = c;
		}
	}
}

static int
compose_pair(uint32_t a, uint32_t b, uint32_t *out)
{
	const struct nfc_comp	*e;
	struct nfc_comp		 key;

	if (a >= HANGUL_LBASE && a < HANGUL_LBASE + HANGUL_LCOUNT &&
	    b >= HANGUL_VBASE && b < HANGUL_VBASE + HANGUL_VCOUNT) {
		*out = NFC_HANGUL_FIRST + ((a - HANGUL_LBASE) * HANGUL_VCOUNT +
		    (b - HANGUL_VBASE)) * HANGUL_TCOUNT;
		return (1);
	}
	if (a >= NFC_HANGUL_FIRST && a <= NFC_HANGUL_LAST &&
	    (a - NFC_HANGUL_FIRST) % HANGUL_TCOUNT == 0 &&
	    b > HANGUL_TBASE && b < HANGUL_TBASE + HANGUL_TCOUNT) {
		*out = a + (b - HANGUL_TBASE);
		return (1);
	}

	key.first = a;
	key.second = b;
	key.comp = 0;
	e = bsearch(&key, nfc_comp, nitems(nfc_comp), sizeof(nfc_comp[0]),
	    comp_cmp);
	if (e == NULL)
		return (0);
	*out = e->comp;
	return (1);
}

/*
 * A character composes with the last starter unless a character between
 * them has the same or a higher combining class.  Until the first starter,
 * nothing composes.
 */
static size_t
compose(uint32_t *d, uint8_t *cc, size_t n)
{
	uint32_t	c;
	size_t		starter, out, i;
	int		last;

	if (n == 0)
		return (0);

	starter = 0;
	last = cc[0] == 0 ? 0 : 256;
	out = 1;
	for (i = 1; i < n; i++) {
		if ((last < cc[i] || last == 0) &&
		    compose_pair(d[starter], d[i], &c)) {
			d[starter] = c;
			continue;
		}
		if (cc[i] == 0)
			starter = out;
		last = cc[i];
		d[out] = d[i];
		cc[out] = cc[i];
		out++;
	}
	return (out);
}

/*
 * Assigned means any General_Category but Cn.  Private use is assigned,
 * and noncharacters are not.
 */
int
nfc_assigned_ok(const char *name)
{
	const unsigned char	*p = (const unsigned char *)name;
	uint32_t		 cp;
	size_t			 left, len;

	left = strlen(name);
	while (left > 0) {
		if (!utf8_char(p, left, &len))
			return (0);
		cp = utf8_decode(p, len);
		if (bsearch(&cp, nfc_assigned, nitems(nfc_assigned),
		    sizeof(nfc_assigned[0]), range_cmp) == NULL)
			return (0);
		p += len;
		left -= len;
	}
	return (1);
}

int
nfc_ok(const char *name)
{
	const unsigned char	*p = (const unsigned char *)name;
	uint32_t		 in[MBOX_NAME_MAX], d[NFC_BUF_MAX];
	uint8_t			 cc[NFC_BUF_MAX];
	size_t			 left, len, nin, n, i;

	left = strlen(name);
	if (left >= MBOX_NAME_MAX)
		fatalx("nfc: name too long");

	nin = n = 0;
	while (left > 0) {
		if (!utf8_char(p, left, &len))
			return (0);
		in[nin] = utf8_decode(p, len);
		decompose(in[nin], d, &n);
		nin++;
		p += len;
		left -= len;
	}

	for (i = 0; i < n; i++)
		cc[i] = ccc_of(d[i]);
	reorder(d, cc, n);
	n = compose(d, cc, n);

	if (n != nin)
		return (0);
	return (memcmp(in, d, n * sizeof(d[0])) == 0);
}
