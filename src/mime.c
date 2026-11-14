#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "store_internal.h"

/* One field with its continuation lines. */
struct hdr_field {
	size_t	start;
	size_t	name_end;
	size_t	colon;
	size_t	line_end;
	size_t	end;
};

static int		 locate_mime_part(int, const struct mime_part *,
		    const int *, int, struct mime_part *);
static int		 mime_part_multipart(const struct mime_part *);
static int		 mime_part_message(const struct mime_part *);
static int		 section_text_range(const struct mime_part *, int,
		    const char **, size_t *);
static int		 mime_part_load(int, const char *, const char *,
		    char **, struct mime_part *);
static int		 cur_snap_cmp(const void *, const void *);
static int		 cur_snapshot_build(struct cur_snapshot *, int);
static const char	*cur_snapshot_find(struct cur_snapshot *, int,
		    const char *, size_t);
static int		 cur_entry_take(const char *, size_t, char *, size_t,
		    char *, size_t);
static int		 scan_cur_for_basename(struct cur_snapshot *, int,
		    const char *, char *, size_t, char *, size_t);
static int		 header_field_name_matches(const char *, size_t,
		    const char *);
static int		 hdr_next_field(const char *, size_t, size_t *,
		    struct hdr_field *);
static int		 filter_header_fields(const char *, size_t,
		    const char *, int, char *, size_t *);
static int		 mime_is_tspecial(char);
static int		 mime_read_value(const char *, size_t, size_t *, char *,
		    size_t, size_t *);
static void		 mime_str_upper(char *);
static int		 content_type_value(const char *, size_t,
		    struct content_type *, char **, size_t *, size_t *);
static int		 find_mime_part(int, const struct mime_part *,
		    const int *, int, struct mime_part *);
static int		 flag_append(char *, size_t, int *, const char *);

static int
cur_snap_cmp(const void *a, const void *b)
{
	return (strcmp(*(const char * const *)a, *(const char * const *)b));
}

void
cur_snapshot_discard(struct cur_snapshot *snap)
{
	size_t	i;

	for (i = 0; i < snap->n; i++)
		free(snap->names[i]);
	free(snap->names);
	snap->names = NULL;
	snap->n = 0;
	snap->dfd = -1;
	snap->failed = 0;
}

static int
cur_snapshot_build(struct cur_snapshot *snap, int dfd)
{
	const struct dirent	*de;
	size_t			  n = 0, cap = 0;
	char			**names = NULL, **tmp;
	DIR			*dp;

	cur_snapshot_discard(snap);

	if ((dp = opendirat(dfd, "cur")) == NULL) {
		snap->failed = 1;
		return (-1);
	}
	while ((de = readdir(dp)) != NULL) {
		/* Skip the dot entries, as delivery makes no dotfiles. */
		if (de->d_name[0] == '.')
			continue;
		if (n == cap) {
			cap = cap != 0 ? cap * 2 : 64;
			tmp = reallocarray(names, cap, sizeof(*names));
			if (tmp == NULL)
				goto fail;
			names = tmp;
		}
		if ((names[n] = strdup(de->d_name)) == NULL)
			goto fail;
		n++;
	}
	closedir(dp);
	if (n > 1)
		qsort(names, n, sizeof(*names), cur_snap_cmp);
	snap->names = names;
	snap->n = n;
	snap->dfd = dfd;
	return (0);

fail:
	log_warn("reading cur/ into a snapshot");
	while (n > 0)
		free(names[--n]);
	free(names);
	closedir(dp);
	snap->failed = 1;
	return (-1);
}

static const char *
cur_snapshot_find(struct cur_snapshot *snap, int dfd, const char *basename,
    size_t baselen)
{
	size_t	lo = 0, hi, mid;
	int	c;

	if (snap->dfd != dfd) {
		if (snap->failed)
			return (NULL);
		if (cur_snapshot_build(snap, dfd) == -1)
			return (NULL);
	}
	hi = snap->n;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if ((c = strncmp(snap->names[mid], basename, baselen)) == 0)
			c = (unsigned char)snap->names[mid][baselen] - ':';
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < snap->n &&
	    strncmp(snap->names[lo], basename, baselen) == 0 &&
	    snap->names[lo][baselen] == ':')
		return (snap->names[lo]);
	return (NULL);
}

static int
cur_entry_take(const char *name, size_t baselen, char *path, size_t pathsize,
    char *suffix_out, size_t suffix_out_size)
{
	int	ret;

	ret = snprintf(path, pathsize, "cur/%s", name);
	if (ret < 0 || (size_t)ret >= pathsize)
		return (-1);
	if (suffix_out != NULL && strlcpy(suffix_out, name + baselen,
	    suffix_out_size) >= suffix_out_size) {
		log_warnx("%s: flag suffix truncated", name);
		return (-1);
	}
	return (0);
}

static int
scan_cur_for_basename(struct cur_snapshot *snap, int dfd,
    const char *basename, char *path, size_t pathsize,
    char *suffix_out, size_t suffix_out_size)
{
	const struct dirent	*de;
	const char		*hit;
	size_t			 baselen;
	DIR			*dp;
	int			 rv = -1;

	baselen = strlen(basename);
	if ((hit = cur_snapshot_find(snap, dfd, basename, baselen)) != NULL)
		return (cur_entry_take(hit, baselen, path, pathsize,
		    suffix_out, suffix_out_size));

	/* It may have arrived since the snapshot, so look. */
	if ((dp = opendirat(dfd, "cur")) == NULL) {
		if (errno != ENOENT)
			log_warn("opendir cur");
		return (-1);
	}
	while ((de = readdir(dp)) != NULL) {
		if (strncmp(de->d_name, basename, baselen) != 0 ||
		    de->d_name[baselen] != ':')
			continue;
		rv = cur_entry_take(de->d_name, baselen, path, pathsize,
		    suffix_out, suffix_out_size);
		break;
	}
	closedir(dp);
	return (rv);
}

int
locate_message_file(struct cur_snapshot *snap, int dfd, const char *basename,
    off_t *size_out, char *suffix_out, size_t suffix_out_size)
{
	struct stat	 st;
	const char	*hit;
	size_t		 baselen;
	char		 path[PATH_MAX];
	int		 ret;

	baselen = strlen(basename);
	suffix_out[0] = '\0';

	if ((hit = cur_snapshot_find(snap, dfd, basename, baselen)) != NULL) {
		if (cur_entry_take(hit, baselen, path, sizeof(path),
		    suffix_out, suffix_out_size) == -1)
			return (-1);
		/* Callers passing no size hold LOCK_EX, so no recheck. */
		if (size_out == NULL)
			return (0);
		if (fstatat(dfd, path, &st, 0) == 0) {
			*size_out = st.st_size;
			return (0);
		}
		if (errno != ENOENT)
			return (-1);
		/* Renamed since cur/ was read, so read it again. */
		cur_snapshot_discard(snap);
		suffix_out[0] = '\0';
	}

	ret = snprintf(path, sizeof(path), "new/%s", basename);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		log_warnx("basename too long: %s", basename);
		return (-1);
	}
	if (fstatat(dfd, path, &st, 0) == 0) {
		if (size_out != NULL)
			*size_out = st.st_size;
		return (0);
	}
	if (errno != ENOENT) {
		log_warn("stat %s", path);
		return (-1);
	}

	if (scan_cur_for_basename(snap, dfd, basename, path, sizeof(path),
	    suffix_out, suffix_out_size) == -1)
		return (-1);
	if (size_out == NULL)
		return (0);
	if (fstatat(dfd, path, &st, 0) == -1)
		return (-1);
	*size_out = st.st_size;
	return (0);
}

int
open_message_file(struct cur_snapshot *snap, int dfd, const char *basename)
{
	char	 path[PATH_MAX];
	int	 fd, ret;

	ret = snprintf(path, sizeof(path), "new/%s", basename);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		log_warnx("basename too long: %s", basename);
		return (-1);
	}
	if ((fd = openat(dfd, path, O_RDONLY)) != -1)
		return (fd);
	if (errno != ENOENT) {
		log_warn("open %s", path);
		return (-1);
	}

	if (scan_cur_for_basename(snap, dfd, basename, path, sizeof(path),
	    NULL, 0) == -1)
		return (-1);
	if ((fd = openat(dfd, path, O_RDONLY)) != -1 || errno != ENOENT)
		return (fd);
	cur_snapshot_discard(snap);
	if (scan_cur_for_basename(snap, dfd, basename, path, sizeof(path),
	    NULL, 0) == -1)
		return (-1);
	return (openat(dfd, path, O_RDONLY));
}

int
read_message_header(struct cur_snapshot *snap, int dfd, const char *basename,
    char **buf_out, uint32_t *len_out)
{
	int	 fd, rc;

	if ((fd = open_message_file(snap, dfd, basename)) == -1)
		return (-1);
	rc = read_header_from_fd(fd, basename, buf_out, len_out);
	close(fd);
	return (rc);
}

/*
 * Read by descriptor, as the parser lacks rpath.
 */
int
read_header_from_fd(int fd, const char *basename, char **buf_out,
    uint32_t *len_out)
{
	ssize_t	 n, total = 0;
	size_t	 i, hdrend = 0, sepindex;
	char	 readbuf[FETCH_HEADER_MAX + 1];

	while (total < (ssize_t)sizeof(readbuf)) {
		n = read(fd, readbuf + total, sizeof(readbuf) - total);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			log_warn("read message header (%s)", basename);
			return (-1);
		}
		if (n == 0)
			break;
		total += n;
	}

	/* End of file within the cap ends a header. */
	if (find_header_body_split(readbuf, (size_t)total, &hdrend) == 0)
		sepindex = hdrend;
	else if (total > 0 && total <= FETCH_HEADER_MAX)
		sepindex = (size_t)total;
	else
		sepindex = sizeof(readbuf);

	for (i = 0; i < sepindex && i < (size_t)total; i++) {
		if (readbuf[i] == '\0') {
			log_warnx("message %s: NUL in header, "
			    "BODY.PEEK[HEADER] skipped", basename);
			return (-1);
		}
	}

	if (sepindex > FETCH_HEADER_MAX) {
		log_warnx("message %s: no header end within %d bytes, "
		    "BODY.PEEK[HEADER] skipped", basename, FETCH_HEADER_MAX);
		return (-1);
	}

	if ((*buf_out = malloc(sepindex)) == NULL) {
		log_warn("malloc message header (%s)", basename);
		return (-1);
	}
	memcpy(*buf_out, readbuf, sepindex);
	*len_out = (uint32_t)sepindex;
	return (0);
}

int
read_body_from_fd(int fd, const char *basename, int text_only,
    size_t maxlen, const char *label, char **buf_out,
    uint32_t *len_out)
{
	struct stat	 st;
	ssize_t		 n, total = 0;
	size_t		 readbuf_size;
	size_t		 i, hdrend, sepindex = 0;
	char		*readbuf = NULL;

	*buf_out = NULL;
	*len_out = 0;

	if (fstat(fd, &st) == -1) {
		log_warn("%s: fstat", basename);
		return (-1);
	}
	if (!S_ISREG(st.st_mode)) {
		log_warnx("%s: not a regular file, %s skipped", basename,
		    label);
		return (-1);
	}
	if ((uint64_t)st.st_size > (uint64_t)maxlen)
		goto toolarge;
	readbuf_size = (size_t)st.st_size + 1;

	if ((readbuf = malloc(readbuf_size)) == NULL) {
		log_warn("malloc message body readbuf (%s)", basename);
		return (-1);
	}

	while (total < (ssize_t)readbuf_size) {
		n = read(fd, readbuf + total, readbuf_size - total);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			log_warn("read message body (%s)", basename);
			free(readbuf);
			return (-1);
		}
		if (n == 0)
			break;
		total += n;
	}

	if (total > (ssize_t)maxlen)
		goto toolarge;

	for (i = 0; i < (size_t)total; i++) {
		if (readbuf[i] == '\0') {
			log_warnx("message %s has a NUL byte, %s skipped",
			    basename, label);
			free(readbuf);
			return (-1);
		}
	}

	if (text_only) {
		if (find_header_body_split(readbuf, (size_t)total, &hdrend)
		    == -1) {
			log_warnx("message %s: no header/body separator "
			    "found, %s skipped", basename, label);
			free(readbuf);
			return (-1);
		}
		sepindex = hdrend;
	}

	/* A sepindex of 0 means the whole message. */
	*len_out = (uint32_t)((size_t)total - sepindex);
	if (*len_out > 0) {
		if ((*buf_out = malloc(*len_out)) == NULL) {
			log_warn("malloc message body (%s)", basename);
			*len_out = 0;
			free(readbuf);
			return (-1);
		}
		memcpy(*buf_out, readbuf + sepindex, *len_out);
	}
	free(readbuf);
	return (0);

toolarge:
	log_warnx("message %s exceeds %zu bytes, %s skipped", basename, maxlen,
	    label);
	free(readbuf);
	return (-1);
}

/*
 * Match case-insensitively in the ASCII range only.
 */
static int
header_field_name_matches(const char *name, size_t namelen, const char *list)
{
	char	 listcopy[HEADER_FIELDS_MAX];
	char	*tok, *p;

	if (namelen == 0 || namelen >= sizeof(listcopy))
		return (0);

	strlcpy(listcopy, list, sizeof(listcopy));
	p = listcopy;
	while ((tok = strsep(&p, " ")) != NULL) {
		if (strlen(tok) == namelen &&
		    strncasecmp(tok, name, namelen) == 0)
			return (1);
	}
	return (0);
}

#define HDR_FIELD_GOT	1
#define HDR_FIELD_END	0
#define HDR_FIELD_ERR	(-1)

static int
hdr_next_field(const char *hdr, size_t hdrlen, size_t *off,
    struct hdr_field *f)
{
	size_t	i, j;

	if (*off >= hdrlen)
		return (HDR_FIELD_ERR);

	f->start = *off;

	i = *off;
	while (i < hdrlen && hdr[i] != '\n')
		i++;
	if (i >= hdrlen)
		return (HDR_FIELD_ERR);	/* The last line has no LF. */

	f->line_end = (i > f->start && hdr[i - 1] == '\r') ? i - 1 : i;
	*off = i + 1;

	if (f->line_end == f->start) {
		f->colon = f->name_end = f->line_end;
		f->end = *off;
		return (HDR_FIELD_END);
	}

	for (f->colon = f->start; f->colon < f->line_end; f->colon++) {
		if (hdr[f->colon] == ':')
			break;
	}
	/* Obsolete syntax allows white space before the colon. */
	f->name_end = f->colon;
	while (f->colon < f->line_end && f->name_end > f->start &&
	    (hdr[f->name_end - 1] == ' ' || hdr[f->name_end - 1] == '\t'))
		f->name_end--;

	while (*off < hdrlen && (hdr[*off] == ' ' || hdr[*off] == '\t')) {
		j = *off;
		while (j < hdrlen && hdr[j] != '\n')
			j++;
		if (j >= hdrlen) {
			*off = hdrlen;
			break;
		}
		*off = j + 1;
	}

	f->end = *off;
	return (HDR_FIELD_GOT);
}

static int
filter_header_fields(const char *hdr, size_t hdrlen, const char *fields_spec,
    int want_not, char *out, size_t *outlen_out)
{
	struct hdr_field	 f;
	size_t			 outlen = 0;
	size_t			 off = 0;
	int			 matched, include, r;

	*outlen_out = 0;

	for (;;) {
		if (off == hdrlen) {
			*outlen_out = outlen;
			return (0);
		}
		r = hdr_next_field(hdr, hdrlen, &off, &f);
		if (r == HDR_FIELD_ERR)
			return (-1);
		if (r == HDR_FIELD_END) {
			/* The blank line is included. */
			memcpy(out + outlen, hdr + f.start, f.end - f.start);
			outlen += f.end - f.start;
			*outlen_out = outlen;
			return (0);
		}

		matched = header_field_name_matches(hdr + f.start,
		    f.name_end - f.start, fields_spec);
		include = want_not ? !matched : matched;

		if (include) {
			memcpy(out + outlen, hdr + f.start, f.end - f.start);
			outlen += f.end - f.start;
		}
	}
}

/*
 * Read by descriptor, as the parser lacks rpath.
 */
int
read_message_header_fields(int fd, const char *basename,
    const char *fields_spec, int want_not, char **buf_out,
    uint32_t *len_out)
{
	uint32_t	 hdrlen = 0;
	size_t		 outlen = 0;
	char		*hdrbuf = NULL;
	char		*out;

	*buf_out = NULL;
	*len_out = 0;

	if (read_header_from_fd(fd, basename, &hdrbuf, &hdrlen) == -1)
		return (-1);

	if ((out = malloc(hdrlen)) == NULL) {
		log_warn("malloc HEADER.FIELDS buffer (%s)", basename);
		free(hdrbuf);
		return (-1);
	}

	if (filter_header_fields(hdrbuf, hdrlen, fields_spec, want_not, out,
	    &outlen) == -1) {
		free(hdrbuf);
		free(out);
		return (-1);
	}

	free(hdrbuf);
	*buf_out = out;
	*len_out = (uint32_t)outlen;
	return (0);
}

/*
 * Unfold the value.  A missing field returns -1, so the caller can send
 * NIL.
 */
int
extract_header_field(const char *hdr, size_t hdrlen, const char *name,
    char **val_out, size_t *vallen_out)
{
	struct hdr_field	 f;
	size_t			 namelen, vstart, vend, p, outlen;
	size_t			 off = 0;
	char			*out;

	namelen = strlen(name);
	*val_out = NULL;
	*vallen_out = 0;

	for (;;) {
		outlen = 0;

		if (hdr_next_field(hdr, hdrlen, &off, &f) != HDR_FIELD_GOT)
			return (-1);

		if (f.name_end - f.start != namelen ||
		    strncasecmp(hdr + f.start, name, namelen) != 0)
			continue;

		vstart = f.colon + 1;
		vend = f.end;
		if (vend > vstart && hdr[vend - 1] == '\n')
			vend--;
		if (vend > vstart && hdr[vend - 1] == '\r')
			vend--;
		while (vstart < vend &&
		    (hdr[vstart] == ' ' || hdr[vstart] == '\t'))
			vstart++;

		if ((out = malloc(vend - vstart + 1)) == NULL)
			return (-1);

		for (p = vstart; p < vend; ) {
			if (hdr[p] == '\r' && p + 1 < vend &&
			    hdr[p + 1] == '\n') {
				p += 2;
				continue;
			}
			if (hdr[p] == '\n') {
				p += 1;
				continue;
			}
			out[outlen++] = hdr[p];
			p++;
		}

		*val_out = out;
		*vallen_out = outlen;
		return (0);
	}
}

int
header_next_field(const char *hdr, size_t hdrlen, size_t *off,
    const char **name, size_t *namelen, const char **val, size_t *vallen)
{
	struct hdr_field	 f;
	size_t			 vstart;

	for (;;) {
		if (hdr_next_field(hdr, hdrlen, off, &f) != HDR_FIELD_GOT)
			return (0);
		/* A line with no colon is not a field. */
		if (f.colon == f.line_end)
			continue;
		vstart = f.colon + 1;
		while (vstart < f.end &&
		    (hdr[vstart] == ' ' || hdr[vstart] == '\t'))
			vstart++;
		*name = hdr + f.start;
		*namelen = f.name_end - f.start;
		*val = hdr + vstart;
		*vallen = f.end - vstart;
		return (1);
	}
}

int
find_header_body_split(const char *buf, size_t len, size_t *hdrend_out)
{
	const char	*line, *lf;

	/* The first empty line, ending in LF or CRLF. */
	for (line = buf; (lf = memchr(line, '\n', len - (line - buf))) != NULL;
	    line = lf + 1) {
		if (lf == line || (lf == line + 1 && *line == '\r')) {
			*hdrend_out = lf + 1 - buf;
			return (0);
		}
	}
	return (-1);
}

/*
 * RFC 2045 section 5.1 tspecials.
 */
static int
mime_is_tspecial(char c)
{
	return (strchr("()<>@,;:\\\"/[]?=", c) != NULL);
}

static int
mime_read_value(const char *s, size_t len, size_t *pos, char *out,
    size_t outsize, size_t *needp)
{
	size_t	 outlen = 0;
	char	 c;

	if (outsize == 0)
		return (-1);

	if (*pos < len && s[*pos] == '"') {
		(*pos)++;
		while (*pos < len && s[*pos] != '"') {
			c = s[*pos];

			if (c == '\\' && *pos + 1 < len) {
				(*pos)++;
				c = s[*pos];
			}
			/* NUL becomes a space, as it would end out. */
			if (c == '\0')
				c = ' ';
			if (outlen + 1 < outsize)
				out[outlen] = c;
			outlen++;
			(*pos)++;
		}
		if (*pos >= len)
			return (-1);	/* Unterminated quoted string. */
		(*pos)++;
		out[outlen < outsize ? outlen : outsize - 1] = '\0';
		*needp = outlen;
		return (0);
	}

	while (*pos < len && !mime_is_tspecial(s[*pos]) &&
	    s[*pos] != ' ' && s[*pos] != '\t' &&
	    (unsigned char)s[*pos] >= 0x20 && (unsigned char)s[*pos] != 0x7f) {
		if (outlen + 1 < outsize)
			out[outlen] = s[*pos];
		outlen++;
		(*pos)++;
	}
	out[outlen < outsize ? outlen : outsize - 1] = '\0';
	*needp = outlen;
	if (outlen == 0)
		return (-1);
	return (0);
}

int
mime_read_token_or_qstring(const char *s, size_t len, size_t *pos,
    char *out, size_t outsize)
{
	size_t	 need;

	if (mime_read_value(s, len, pos, out, outsize, &need) == -1)
		return (-1);
	if (need >= outsize)
		return (-1);
	return (0);
}

static void
mime_str_upper(char *s)
{
	for (; *s != '\0'; s++) {
		if (*s >= 'a' && *s <= 'z')
			*s -= ('a' - 'A');
	}
}

/*
 * Read the type, or fall back to text/plain.
 */
static int
content_type_value(const char *hdr, size_t hdrlen, struct content_type *ct,
    char **valp, size_t *vallenp, size_t *posp)
{
	size_t	 vallen = 0, pos = 0;
	char	*val = NULL;

	memset(ct, 0, sizeof(*ct));
	if (extract_header_field(hdr, hdrlen, "Content-Type", &val,
	    &vallen) == 0 && vallen > 0 &&
	    mime_read_token_or_qstring(val, vallen, &pos, ct->type,
	    sizeof(ct->type)) == 0 && pos < vallen && val[pos] == '/') {
		pos++;
		if (mime_read_token_or_qstring(val, vallen, &pos, ct->subtype,
		    sizeof(ct->subtype)) == 0) {
			mime_str_upper(ct->type);
			mime_str_upper(ct->subtype);
			*valp = val;
			*vallenp = vallen;
			*posp = pos;
			return (1);
		}
	}
	free(val);
	strlcpy(ct->type, "TEXT", sizeof(ct->type));
	strlcpy(ct->subtype, "PLAIN", sizeof(ct->subtype));
	return (0);
}

/*
 * Read the next attribute and value, and return 1.  Return 0 at the end.
 */
int
content_type_param(const char *val, size_t vallen, size_t *posp,
    struct content_param *p)
{
	size_t	 pos = *posp, attrlen, valuelen;

	while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
		pos++;
	if (pos >= vallen || val[pos] != ';')
		return (0);
	pos++;
	while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
		pos++;
	if (mime_read_value(val, vallen, &pos, p->attr, sizeof(p->attr),
	    &attrlen) == -1)
		return (0);
	while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
		pos++;
	if (pos >= vallen || val[pos] != '=')
		return (0);
	pos++;
	while (pos < vallen && (val[pos] == ' ' || val[pos] == '\t'))
		pos++;
	if (mime_read_value(val, vallen, &pos, p->value, sizeof(p->value),
	    &valuelen) == -1)
		return (0);
	p->toolong = attrlen >= sizeof(p->attr) ||
	    valuelen >= sizeof(p->value);
	mime_str_upper(p->attr);
	*posp = pos;
	return (1);
}

void
parse_content_type(const char *hdr, size_t hdrlen, struct content_type *ct)
{
	struct content_param	 p;
	size_t			 vallen, pos;
	char			*val;

	if (!content_type_value(hdr, hdrlen, ct, &val, &vallen, &pos))
		return;
	while (content_type_param(val, vallen, &pos, &p)) {
		if (strcasecmp(p.attr, "BOUNDARY") == 0 &&
		    strlcpy(ct->boundary, p.value, sizeof(ct->boundary)) <
		    sizeof(ct->boundary))
			ct->has_boundary = 1;
	}
	free(val);
}

/*
 * RFC 9051 section 9 body-fld-param.
 */
int
content_type_params(const char *hdr, size_t hdrlen, char *out,
    size_t outsize, size_t *outlen)
{
	struct content_type	 ct;
	struct content_param	 p;
	size_t			 vallen, pos;
	char			*val;
	int			 n = 0, rc = 0;

	if (!content_type_value(hdr, hdrlen, &ct, &val, &vallen, &pos))
		return (envbuf_append_str(out, outsize, outlen,
		    "(\"CHARSET\" \"US-ASCII\")"));
	while (rc == 0 && content_type_param(val, vallen, &pos, &p)) {
		if (p.toolong ||
		    envbuf_append_str(out, outsize, outlen,
		    n++ == 0 ? "(" : " ") == -1 ||
		    envbuf_append_nstring(out, outsize, outlen, p.attr,
		    strlen(p.attr)) == -1 ||
		    envbuf_append(out, outsize, outlen, " ", 1) == -1 ||
		    envbuf_append_nstring(out, outsize, outlen, p.value,
		    strlen(p.value)) == -1)
			rc = -1;
	}
	free(val);
	if (rc == -1)
		return (-1);
	return (envbuf_append_str(out, outsize, outlen, n > 0 ? ")" : "NIL"));
}

int
split_multipart(const char *body, size_t bodylen, const char *boundary,
    size_t *part_starts, size_t *part_ends, int *nparts_out, int maxparts)
{
	size_t	 needlelen, after, content_end, part_start;
	size_t	 pos = 0;
	char	 needle[2 + MIME_BOUNDARY_MAX + 1];
	int	 found_first = 0, at_bol, is_close;
	int	 n = 0;
	int	 closed = 0;

	strlcpy(needle, "--", sizeof(needle));
	needlelen = strlcat(needle, boundary, sizeof(needle));
	if (needlelen >= sizeof(needle))
		return (-1);	/* Over 70 characters. */

	*nparts_out = 0;

	while (pos < bodylen) {
		at_bol = (pos == 0) ||
		    (pos >= 2 && body[pos - 2] == '\r' &&
		    body[pos - 1] == '\n') ||
		    (pos >= 1 && body[pos - 1] == '\n');
		is_close = 0;

		if (!at_bol || pos + needlelen > bodylen ||
		    memcmp(body + pos, needle, needlelen) != 0) {
			pos++;
			continue;
		}

		after = pos + needlelen;
		if (after + 1 < bodylen && body[after] == '-' &&
		    body[after + 1] == '-') {
			is_close = 1;
			after += 2;
		}
		while (after < bodylen &&
		    (body[after] == ' ' || body[after] == '\t'))
			after++;
		if (after < bodylen && body[after] != '\r' &&
		    body[after] != '\n') {
			/* A coincidental match, not a delimiter. */
			pos++;
			continue;
		}

		if (found_first) {
			content_end = pos;
			part_start = part_starts[n - 1];

			/* An empty part must not underflow the length. */
			if (content_end >= part_start + 2 &&
			    body[content_end - 2] == '\r' &&
			    body[content_end - 1] == '\n')
				content_end -= 2;
			else if (content_end >= part_start + 1 &&
			    body[content_end - 1] == '\n')
				content_end -= 1;
			part_ends[n - 1] = content_end;
		}

		if (is_close) {
			closed = 1;
			break;
		}

		if (after < bodylen && body[after] == '\r' &&
		    after + 1 < bodylen && body[after + 1] == '\n')
			after += 2;
		else if (after < bodylen && body[after] == '\n')
			after += 1;
		else
			break;

		if (n >= maxparts)
			return (-1);
		part_starts[n] = after;
		n++;
		found_first = 1;
		pos = after;
	}

	if (!closed || !found_first)
		return (-1);

	*nparts_out = n;
	return (0);
}

/*
 * RFC 9051 section 6.4.5.1 section-part.
 */
int
parse_section_part(const char *s, int *path, int maxpath)
{
	char	*end;
	long	 val;
	int	 n = 0;

	if (s == NULL || *s == '\0')
		return (-1);

	while (*s != '\0') {
		if (*s < '1' || *s > '9')	/* No leading zero. */
			return (-1);
		if (n >= maxpath)
			return (-1);

		errno = 0;
		val = strtol(s, &end, 10);
		if (val <= 0 || val > INT_MAX || errno != 0)
			return (-1);
		path[n++] = (int)val;

		s = end;
		if (*s == '\0')
			break;
		if (*s != '.')
			return (-1);
		s++;
		if (*s == '\0')
			return (-1);
	}
	return (n);
}

static int
find_mime_part(int depth, const struct mime_part *in, const int *path,
    int pathlen, struct mime_part *out)
{
	struct content_type	 ct;
	struct mime_part	 sub;
	const char		*pbuf;
	size_t			 part_starts[MIME_MAX_PARTS];
	size_t			 part_ends[MIME_MAX_PARTS];
	size_t			 plen, phdrend, ih;
	int			 n, want;

	if (depth > MIME_MAX_DEPTH)
		return (-1);

	parse_content_type(in->hdr, in->hdrlen, &ct);
	if (strcasecmp(ct.type, "MULTIPART") != 0 || !ct.has_boundary)
		return (-1);
	if (split_multipart(in->body, in->bodylen, ct.boundary, part_starts,
	    part_ends, &n, MIME_MAX_PARTS) == -1)
		return (-1);

	want = path[0];
	if (want < 1 || want > n)
		return (-1);	/* No such part here. */

	pbuf = in->body + part_starts[want - 1];
	plen = part_ends[want - 1] - part_starts[want - 1];
	if (plen == 0)
		phdrend = 0;
	else if (find_header_body_split(pbuf, plen, &phdrend) == -1)
		phdrend = plen;

	sub.hdr = pbuf;
	sub.hdrlen = phdrend;
	sub.body = pbuf + phdrend;
	sub.bodylen = plen - phdrend;
	if (pathlen == 1) {
		*out = sub;
		return (0);
	}

	/* A message's parts are numbered within it. */
	parse_content_type(sub.hdr, sub.hdrlen, &ct);
	if (strcasecmp(ct.type, "MESSAGE") == 0 &&
	    (strcasecmp(ct.subtype, "RFC822") == 0 ||
	    strcasecmp(ct.subtype, "GLOBAL") == 0)) {
		if (sub.bodylen == 0)
			return (-1);
		if (find_header_body_split(sub.body, sub.bodylen, &ih) == -1)
			ih = sub.bodylen;
		sub.hdr = sub.body;
		sub.hdrlen = ih;
		sub.body += ih;
		sub.bodylen -= ih;
		return (locate_mime_part(depth + 1, &sub, path + 1, pathlen - 1,
		    out));
	}

	return (find_mime_part(depth + 1, &sub, path + 1, pathlen - 1, out));
}

/*
 * A non-multipart message is its own part 1.
 */
static int
locate_mime_part(int depth, const struct mime_part *in, const int *path,
    int pathlen, struct mime_part *out)
{
	struct content_type	 ct;
	struct mime_part	 sub;
	size_t			 ih;

	if (depth > MIME_MAX_DEPTH || pathlen < 1)
		return (-1);

	parse_content_type(in->hdr, in->hdrlen, &ct);

	if (strcasecmp(ct.type, "MULTIPART") == 0)
		return (find_mime_part(depth + 1, in, path, pathlen, out));

	if (path[0] != 1)
		return (-1);
	if (pathlen == 1) {
		*out = *in;
		return (0);
	}
	if (strcasecmp(ct.type, "MESSAGE") != 0 ||
	    (strcasecmp(ct.subtype, "RFC822") != 0 &&
	    strcasecmp(ct.subtype, "GLOBAL") != 0) || in->bodylen == 0)
		return (-1);
	if (find_header_body_split(in->body, in->bodylen, &ih) == -1)
		ih = in->bodylen;
	sub.hdr = in->body;
	sub.hdrlen = ih;
	sub.body = in->body + ih;
	sub.bodylen = in->bodylen - ih;
	return (locate_mime_part(depth + 1, &sub, path + 1, pathlen - 1, out));
}

static int
mime_part_multipart(const struct mime_part *mp)
{
	struct content_type	 ct;

	parse_content_type(mp->hdr, mp->hdrlen, &ct);
	return (strcasecmp(ct.type, "MULTIPART") == 0);
}

static int
mime_part_message(const struct mime_part *mp)
{
	struct content_type	 ct;

	parse_content_type(mp->hdr, mp->hdrlen, &ct);
	return (strcasecmp(ct.type, "MESSAGE") == 0 &&
	    (strcasecmp(ct.subtype, "RFC822") == 0 ||
	    strcasecmp(ct.subtype, "GLOBAL") == 0));
}

static int
section_text_range(const struct mime_part *mp, int text, const char **startp,
    size_t *lenp)
{
	size_t	 ih;

	if (text == SECTION_TEXT_MIME) {
		*startp = mp->hdr;
		*lenp = mp->hdrlen;
		return (0);
	}
	if ((text != SECTION_TEXT_HEADER && text != SECTION_TEXT_TEXT) ||
	    !mime_part_message(mp))
		return (-1);
	/* Without a blank line, it is all header. */
	if (find_header_body_split(mp->body, mp->bodylen, &ih) == -1)
		ih = mp->bodylen;
	if (text == SECTION_TEXT_HEADER) {
		*startp = mp->body;
		*lenp = ih;
	} else {
		*startp = mp->body + ih;
		*lenp = mp->bodylen - ih;
	}
	return (0);
}

/*
 * Apply a <start.count> partial to the range.  A start past the end gives
 * nothing.
 */
void
partial_range(int has_partial, uint64_t start, uint64_t count,
    uint64_t *off, uint64_t *len)
{
	if (!has_partial)
		return;
	if (start >= *len) {
		*off += *len;
		*len = 0;
		return;
	}
	*off += start;
	*len -= start;
	if (*len > count)
		*len = count;
}

static int
mime_part_load(int fd, const char *basename, const char *label,
    char **wholep, struct mime_part *msg)
{
	uint32_t	 wholelen = 0;
	size_t		 hdrend;

	*wholep = NULL;
	if (read_body_from_fd(fd, basename, 0, bodystructure_read_max, label,
	    wholep, &wholelen) == -1)
		return (-1);
	if (wholelen == 0) {
		free(*wholep);
		*wholep = NULL;
		return (-1);
	}
	if (find_header_body_split(*wholep, wholelen, &hdrend) == -1)
		hdrend = wholelen;
	msg->hdr = *wholep;
	msg->hdrlen = hdrend;
	msg->body = *wholep + hdrend;
	msg->bodylen = wholelen - hdrend;
	return (0);
}

int
extract_mime_part(int fd, const struct imsg_parser_req *req,
    uint64_t *off_out, uint64_t *len_out)
{
	struct mime_part	 msg, part;
	const char		*start;
	size_t			 len;
	char			*wholebuf;
	int			 rc;

	*off_out = 0;
	*len_out = 0;

	if (mime_part_load(fd, req->basename, "BODY[<part>]", &wholebuf,
	    &msg) == -1)
		return (-1);

	/* A missing part is an empty item. */
	if (locate_mime_part(0, &msg, req->path, req->pathlen, &part) == -1) {
		free(wholebuf);
		return (0);
	}
	if (req->section_text != SECTION_TEXT_NONE) {
		rc = section_text_range(&part, req->section_text, &start, &len);
		if (rc == 0) {
			*off_out = (uint64_t)(start - wholebuf);
			*len_out = (uint64_t)len;
		}
		free(wholebuf);
		return (rc);
	}
	/* A multipart is not returned by its number. */
	if (!mime_part_multipart(&part)) {
		*off_out = (uint64_t)(part.body - wholebuf);
		*len_out = (uint64_t)part.bodylen;
	}
	free(wholebuf);
	return (0);
}

int
read_part_header_fields(int fd, const struct imsg_parser_req *req,
    char **buf_out, uint32_t *len_out)
{
	struct mime_part	 msg, part;
	const char		*hdr;
	size_t			 hdrlen, outlen = 0;
	char			*wholebuf, *out;

	*buf_out = NULL;
	*len_out = 0;

	if (mime_part_load(fd, req->basename, "HEADER.FIELDS", &wholebuf,
	    &msg) == -1)
		return (-1);
	if (locate_mime_part(0, &msg, req->path, req->pathlen, &part) == -1) {
		free(wholebuf);
		return (0);
	}
	if (section_text_range(&part, SECTION_TEXT_HEADER, &hdr,
	    &hdrlen) == -1) {
		free(wholebuf);
		return (-1);
	}
	if (hdrlen == 0) {
		free(wholebuf);
		return (0);
	}
	if ((out = malloc(hdrlen)) == NULL) {
		log_warn("malloc HEADER.FIELDS buffer (%s)", req->basename);
		free(wholebuf);
		return (-1);
	}
	if (filter_header_fields(hdr, hdrlen, req->fields, req->fields_not,
	    out, &outlen) == -1) {
		free(out);
		free(wholebuf);
		return (-1);
	}
	free(wholebuf);
	*buf_out = out;
	*len_out = (uint32_t)outlen;
	return (0);
}

int
extract_binary_part(int fd, const struct imsg_parser_req *req, int sink,
    struct imsg_parser_rep *rep)
{
	struct mime_part	 msg, part;
	char			*wholebuf;
	int			 rc = 0;

	if (mime_part_load(fd, req->basename, "BINARY[<part>]", &wholebuf,
	    &msg) == -1)
		return (-1);
	if (locate_mime_part(0, &msg, req->path, req->pathlen, &part) == 0) {
		rep->part_off = (uint64_t)(part.body - wholebuf);
		rep->part_len = (uint64_t)part.bodylen;
		rc = binary_decode(&part, sink, rep);
	}
	free(wholebuf);
	return (rc);
}

int
message_body_range(struct cur_snapshot *snap, int dfd, const char *basename,
    int text_only, uint64_t *off_out, uint64_t *len_out, int *fdbusy_out)
{
	char			 blk[STORE_READ_BLOCK];
	unsigned char		 c, b1 = '\n', b2 = '\n';
	uint64_t		 total = 0, hdrend = 0;
	ssize_t			 n, i;
	int			 fd, found = !text_only;

	*off_out = 0;
	*len_out = 0;
	*fdbusy_out = 0;

	if ((fd = open_message_file(snap, dfd, basename)) == -1) {
		if (errno == EMFILE || errno == ENFILE)
			*fdbusy_out = 1;
		return (-1);
	}

	for (;;) {
		if ((n = read(fd, blk, sizeof(blk))) == -1) {
			if (errno == EINTR)
				continue;
			log_warn("read message body (%s)", basename);
			close(fd);
			return (-1);
		}
		if (n == 0)
			break;
		for (i = 0; i < n; i++) {
			c = (unsigned char)blk[i];
			if (c == '\0') {
				log_warnx("message %s has a NUL byte, BODY[] "
				    "skipped", basename);
				close(fd);
				return (-1);
			}
			/* An empty line ends the header, LF or CRLF. */
			if (!found && c == '\n' && (b1 == '\n' ||
			    (b1 == '\r' && b2 == '\n'))) {
				found = 1;
				hdrend = total + (uint64_t)i + 1;
			}
			b2 = b1;
			b1 = c;
		}
		total += (uint64_t)n;
	}

	/* Without a blank line, the text is empty. */
	if (!found)
		hdrend = total;
	*off_out = hdrend;
	*len_out = total - hdrend;
	return (fd);
}

static int
flag_append(char *out, size_t outsize, int *first, const char *flag)
{
	if ((!*first && strlcat(out, " ", outsize) >= outsize) ||
	    strlcat(out, flag, outsize) >= outsize) {
		log_warnx("flag list truncated");
		return (0);
	}
	*first = 0;
	return (1);
}

/*
 * Turn maildir "2," flag letters into IMAP system flags.
 */
void
build_flags_string(const char *maildir_suffix, const char *keywords,
    char *out, size_t outsize)
{
	static const struct {
		char		 letter;
		const char	*flag;
	} stdflags[] = {
		{ 'D', "\\Draft" },
		{ 'F', "\\Flagged" },
		{ 'R', "\\Answered" },
		{ 'S', "\\Seen" },
		{ 'T', "\\Deleted" },
	};
	const char	*letters;
	char		*kw, *p;
	char		 kwbuf[512];
	size_t		 i;
	int		 first = 1, empty = 0;

	out[0] = '\0';

	letters = strstr(maildir_suffix, "2,");
	letters = (letters != NULL) ? letters + 2 : "";

	for (i = 0; i < nitems(stdflags); i++) {
		if (strchr(letters, stdflags[i].letter) != NULL &&
		    !flag_append(out, outsize, &first, stdflags[i].flag))
			return;
	}

	if (keywords == NULL || keywords[0] == '\0')
		return;
	strlcpy(kwbuf, keywords, sizeof(kwbuf));
	p = kwbuf;
	while ((kw = strsep(&p, ",")) != NULL) {
		if (*kw == '\0') {
			empty = 1;
			continue;
		}
		if (!flag_append(out, outsize, &first, kw))
			return;
	}
	if (empty)
		log_warnx("empty keyword in index, skipped");
}

/* IMAP years have four digits, so stop at 9999. */
#define MAILDIR_TS_MAX	253402300799LL

/*
 * Take the internal date from the basename, not mtime.
 */
int64_t
parse_maildir_timestamp(const char *basename)
{
	long long	 ts;
	char		*ep;

	errno = 0;
	ts = strtoll(basename, &ep, 10);
	if (ep == basename || *ep != '.' || errno != 0 || ts < 0 ||
	    ts > MAILDIR_TS_MAX)
		return ((int64_t)time(NULL));
	return ((int64_t)ts);
}
