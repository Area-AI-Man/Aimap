#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"
#include "mboxname.h"

struct append_parsed {
	char		mailbox[MBOX_NAME_MAX];
	uint32_t	sysflags;
	char		keywords[MBOX_FLAGS_MAX];
	int		has_date;
	int64_t		date;
	uint64_t	litlen;
	int		litnonsync;
};

static int	 parse_date_time(const char *, int64_t *);
static int	 parse_append_args(char *, struct append_parsed *,
		    const char **);

/*
 * RFC 9051 section 9 date-time.
 */
static int
parse_date_time(const char *s, int64_t *out)
{
	static const char	shape[] = "dd-aaa-dddd dd:dd:dd zdddd";
	struct tm		tm;
	int64_t			zoff;
	time_t			t;
	char			mon[4];
	int			day, year, hh, mm, ss, zh, zm, i;

	memset(&tm, 0, sizeof(tm));

	if (strlen(s) != sizeof(shape) - 1)
		return (-1);
	for (i = 0; shape[i] != '\0'; i++) {
		switch (shape[i]) {
		case 'd':
			if (!isdigit((unsigned char)s[i]) &&
			    (i != 0 || s[i] != ' '))
				return (-1);
			break;
		case 'a':
			if (!isalpha((unsigned char)s[i]))
				return (-1);
			break;
		case 'z':
			if (s[i] != '+' && s[i] != '-')
				return (-1);
			break;
		default:
			if (s[i] != shape[i])
				return (-1);
			break;
		}
	}

	day = (s[0] == ' ' ? 0 : s[0] - '0') * 10 + (s[1] - '0');
	year = (s[7] - '0') * 1000 + (s[8] - '0') * 100 +
	    (s[9] - '0') * 10 + (s[10] - '0');
	hh = (s[12] - '0') * 10 + (s[13] - '0');
	mm = (s[15] - '0') * 10 + (s[16] - '0');
	ss = (s[18] - '0') * 10 + (s[19] - '0');
	zh = (s[22] - '0') * 10 + (s[23] - '0');
	zm = (s[24] - '0') * 10 + (s[25] - '0');
	memcpy(mon, s + 3, 3);
	mon[3] = '\0';

	if (day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 ||
	    year < 1970 || zh > 23 || zm > 59)
		return (-1);

	for (i = 0; i < 12; i++) {
		if (strcasecmp(mon, fetch_month_names[i]) == 0)
			break;
	}
	if (i == 12)
		return (-1);

	tm.tm_mday = day;
	tm.tm_mon = i;
	tm.tm_year = year - 1900;
	tm.tm_hour = hh;
	tm.tm_min = mm;
	tm.tm_sec = ss;

	if ((t = timegm(&tm)) == (time_t)-1)
		return (-1);

	zoff = (int64_t)zh * 3600 + (int64_t)zm * 60;
	if (s[21] == '-')
		zoff = -zoff;

	if ((int64_t)t - zoff < 0)
		return (-1);

	*out = (int64_t)t - zoff;
	return (0);
}

static int
parse_append_args(char *args, struct append_parsed *out, const char **errmsg)
{
	const char	*sub_err, *errstr;
	size_t		 dlen, digits_len;
	char		*p = args, *start, *end, *digits_stop;
	char		 datebuf[64];
	char		 digitsbuf[24];
	char		 saved;
	int		 rc;

	memset(out, 0, sizeof(*out));

	if (p == NULL || *p == '\0') {
		*errmsg = "APPEND requires a mailbox name";
		return (-1);
	}

	if (parse_mailbox_name(&p, out->mailbox, sizeof(out->mailbox),
	    errmsg) == -1)
		return (-1);
	if (out->mailbox[0] == '\0') {
		*errmsg = "empty mailbox name";
		return (-1);
	}

	if (*p != '\0' && read_sp(&p, errmsg) == -1)
		return (-1);
	if (*p == '(') {
		start = p;
		if ((end = strchr(p, ')')) == NULL) {
			*errmsg = "unterminated flag list";
			return (-1);
		}
		end++;	/* Keep the ')' in the substring. */
		saved = *end;
		*end = '\0';
		rc = parse_store_flags(start, &out->sysflags, out->keywords,
		    sizeof(out->keywords), &sub_err);
		*end = saved;
		if (rc != 0) {
			*errmsg = sub_err;
			return (rc);
		}
		p = end;
		if (*p != '\0' && read_sp(&p, errmsg) == -1)
			return (-1);
	}

	if (*p == '"') {
		start = p + 1;
		if ((end = strchr(start, '"')) == NULL) {
			*errmsg = "unterminated date-time string";
			return (-1);
		}
		dlen = (size_t)(end - start);
		if (dlen >= sizeof(datebuf)) {
			*errmsg = "date-time string too long";
			return (-1);
		}
		memcpy(datebuf, start, dlen);
		datebuf[dlen] = '\0';
		if (parse_date_time(datebuf, &out->date) == -1) {
			*errmsg = "malformed date-time string";
			return (-1);
		}
		out->has_date = 1;
		p = end + 1;
		if (*p != '\0' && read_sp(&p, errmsg) == -1)
			return (-1);
	}

	if (*p != '{') {
		*errmsg = "expected a message literal";
		return (-1);
	}
	start = p + 1;
	if ((end = strchr(start, '}')) == NULL) {
		*errmsg = "malformed literal announcement";
		return (-1);
	}

	out->litnonsync = (end > start && end[-1] == '+');
	digits_stop = out->litnonsync ? end - 1 : end;
	digits_len = (size_t)(digits_stop - start);

	if (digits_len == 0 || digits_len >= sizeof(digitsbuf)) {
		*errmsg = "malformed literal octet count";
		return (-1);
	}
	memcpy(digitsbuf, start, digits_len);
	digitsbuf[digits_len] = '\0';

	if (digitsbuf[0] < '0' || digitsbuf[0] > '9') {
		*errmsg = "malformed literal octet count";
		return (-1);
	}
	out->litlen = strtonum(digitsbuf, 0, LLONG_MAX, &errstr);
	if (errstr != NULL) {
		*errmsg = "malformed literal octet count";
		return (-1);
	}

	if (end[1] != '\0') {
		*errmsg = "literal must be the final argument";
		return (-1);
	}

	return (0);
}

void
cmd_append(struct session *s, const char *tag, char *args)
{
	struct imsg_mbox_append	 req;
	struct append_parsed	 parsed;
	static const char	 cont[] = "+ Ready for literal data\r\n";
	const char		*errmsg;
	char			 text[96];
	int			 rc;

	rc = parse_append_args(args, &parsed, &errmsg);
	if (rc == -1) {
		session_arg_error(s, tag, errmsg);
		return;
	}
	if (rc == PARSE_NO) {
		session_reply(s, tag, "NO", errmsg);
		return;
	}

	if (parsed.litlen > listener_append_max) {
		(void)snprintf(text, sizeof(text), "[LIMIT] message exceeds "
		    "this server's %llu octet limit",
		    (unsigned long long)listener_append_max);
		session_reply(s, tag, "NO", text);
		return;
	}

	memset(&req, 0, sizeof(req));
	strlcpy(s->cmd.append_mailbox, parsed.mailbox,
	    sizeof(s->cmd.append_mailbox));
	strlcpy(req.mailbox, parsed.mailbox, sizeof(req.mailbox));
	strlcpy(req.keywords, parsed.keywords, sizeof(req.keywords));
	req.sysflags = parsed.sysflags;
	req.has_date = parsed.has_date;
	req.date = parsed.date;
	req.msglen = parsed.litlen;
	s->cmd.append_prev_state = s->state;

	/* The literal follows in pieces as it arrives. */
	if (imsg_compose(&s->store_iev->ibuf, IMSG_MBOX_APPEND, 0, 0, -1,
	    &req, sizeof(req)) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_APPEND", s->id);
		session_reply(s, tag, "NO", "[SERVERBUG] internal error");
		return;
	}

	s->literal_len = parsed.litlen;
	s->literal_remaining = parsed.litlen;
	s->literal_pending = 1;

	/* No continuation for a non-synchronizing literal. */
	if (!parsed.litnonsync)
		session_write(s, cont, sizeof(cont) - 1);

}

void
session_finish_append(struct session *s)
{
	s->state = SESSION_APPENDING;

	/* A failure here must not leave the session busy. */
	if (imsg_compose(&s->store_iev->ibuf, IMSG_MBOX_APPEND_END, 0, 0, -1,
	    NULL, 0) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_APPEND_END",
		    s->id);
		s->state = s->cmd.append_prev_state;
		session_reply(s, s->cmd.pending_tag, "NO",
		    "[SERVERBUG] internal error");
	}
}

void
session_handle_mbox_appended(struct session *s,
    const struct imsg_mbox_appended *res)
{
	char	buf[96];

	s->state = s->cmd.append_prev_state;

	if (res->error != MBOX_OP_OK) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    res->error == MBOX_OP_ERR_NO_SUCH_MAILBOX ?
		    "[TRYCREATE] no such mailbox" :
		    mbox_error_text(res->error, "APPEND", buf, sizeof(buf)));
		return;
	}

	snprintf(buf, sizeof(buf), "[APPENDUID %u %u] APPEND completed",
	    res->uidvalidity, res->uid);
	session_reply(s, s->cmd.pending_tag, "OK", buf);
}
