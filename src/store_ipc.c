#include <sys/types.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aimap.h"
#include "log.h"
#include "listener.h"

union mbox_reply {
	struct imsg_mbox_selected		 selected;
	struct imsg_mbox_status_result		 status;
	struct imsg_mbox_fetch_header		 header;
	struct imsg_mbox_fetch_envelope		 envelope;
	struct imsg_mbox_fetch_bodystructure	 bodystructure;
	struct imsg_mbox_fetch_meta		 meta;
	struct imsg_mbox_expunged		 expunged;
	struct imsg_mbox_copy_mapping		 mapping;
	struct imsg_mbox_search_match		 match;
	struct imsg_mbox_select_vanished	 vanished;
	struct imsg_mbox_store_modified		 modified;
	struct imsg_mbox_view_exists		 exists;
	struct imsg_mbox_idle_refreshed		 refreshed;
	struct imsg_mbox_result			 result;
	struct imsg_mbox_list_item		 item;
	struct imsg_mbox_appended		 appended;
};

static void	 session_handle_mbox_selected(struct session *,
		    const struct imsg_mbox_selected *);
static void	 session_handle_mbox_status_result(struct session *,
		    const struct imsg_mbox_status_result *);
static void	 session_handle_mbox_result(struct session *,
		    struct imsg_mbox_result *);
static void	 session_handle_mbox_list_item(struct session *,
		    const struct imsg_mbox_list_item *);
static void	 session_handle_mbox_copy_mapping(struct session *,
		    const struct imsg_mbox_copy_mapping *);
static void	 session_handle_select_vanished(struct session *,
		    const struct imsg_mbox_select_vanished *);
static void	 session_handle_select_fetch(struct session *,
		    const struct imsg_mbox_fetch_meta *);
static void	 session_handle_view_fetch(struct session *,
		    const struct imsg_mbox_fetch_meta *);
static void	 session_handle_idle_refreshed(struct session *,
		    const struct imsg_mbox_idle_refreshed *);
static void	 session_send_qresync_fetch_response(struct session *,
		    const struct imsg_mbox_fetch_meta *);
static void	 fetch_part_recv(struct session *, struct ibuf *, const char *,
		    int, uint32_t, char **, uint32_t *, int *);
static void	 session_recv_fetch_body(struct session *, struct imsg *);
static void	 session_hold_expunged(struct session *,
		    const struct imsg_mbox_expunged *);
static void	 session_finish_mbox_op(struct session *,
		    const struct imsg_mbox_result *);
static void	 session_finish_list(struct session *,
		    const struct imsg_mbox_result *);
static void	 session_idle_poll(int, short, void *);

static void
fetch_part_recv(struct session *s, struct ibuf *ibuf, const char *what,
    int found, uint32_t declared_len, char **bufp, uint32_t *lenp,
    int *foundp)
{
	size_t	 wirelen;

	free(*bufp);
	*bufp = NULL;
	*lenp = 0;
	*foundp = 0;

	if (!found)
		return;

	wirelen = ibuf_size(ibuf);
	if (wirelen != declared_len) {
		log_warnx("session %u: %s length mismatch (header says %u, "
		    "imsg has %zu)", s->id, what, declared_len, wirelen);
		return;
	}
	if (wirelen == 0) {
		*foundp = 1;
		return;
	}
	if ((*bufp = malloc(wirelen)) == NULL) {
		log_warn("session %u: malloc pending buffer for %s", s->id,
		    what);
		return;
	}
	if (ibuf_get(ibuf, *bufp, wirelen) == -1) {
		log_warnx("bad %s (body)", what);
		free(*bufp);
		*bufp = NULL;
		return;
	}
	*lenp = (uint32_t)wirelen;
	*foundp = 1;
}

static void
session_recv_fetch_body(struct session *s, struct imsg *imsg)
{
	struct imsg_mbox_fetch_body	 bodyhdr;
	int				 bodyfd;

	bodyfd = imsg_get_fd(imsg);
	if (s->cmd.pending_body_fd != -1)
		close(s->cmd.pending_body_fd);
	s->cmd.pending_body_fd = -1;
	s->cmd.pending_body_off = 0;
	s->cmd.pending_body_len = 0;
	s->cmd.pending_body_found = 0;
	if (!recv_fixed(imsg, &bodyhdr, sizeof(bodyhdr),
	    "IMSG_MBOX_FETCH_BODY")) {
		if (bodyfd != -1)
			close(bodyfd);
		return;
	}
	if (!bodyhdr.found || (bodyhdr.length > 0 && bodyfd == -1)) {
		if (bodyhdr.found)
			log_warnx("session %u: IMSG_MBOX_FETCH_BODY without "
			    "its descriptor", s->id);
		if (bodyfd != -1)
			close(bodyfd);
		return;
	}
	s->cmd.pending_body_fd = bodyfd;
	s->cmd.pending_body_off = bodyhdr.offset;
	s->cmd.pending_body_len = bodyhdr.length;
	s->cmd.pending_body_found = 1;
}

/*
 * A MOVE's EXPUNGEs wait until COPYUID has gone out.
 */
static void
session_hold_expunged(struct session *s, const struct imsg_mbox_expunged *ex)
{
	struct imsg_mbox_expunged	*enew;
	uint32_t			 newcap;

	if (s->cmd.move_expunged_n == s->cmd.move_expunged_cap) {
		newcap = s->cmd.move_expunged_cap ?
		    s->cmd.move_expunged_cap * 2 : 16;
		enew = reallocarray(s->cmd.move_expunged, newcap,
		    sizeof(*enew));
		if (enew == NULL) {
			log_warn("session %u: realloc move_expunged", s->id);
			return;
		}
		s->cmd.move_expunged = enew;
		s->cmd.move_expunged_cap = newcap;
	}
	s->cmd.move_expunged[s->cmd.move_expunged_n++] = *ex;
}

void
session_store_dispatch(int fd, short event, void *arg)
{
	union mbox_reply	 u;
	struct session		*s = arg;
	struct imsg		 imsg;
	struct ibuf		 ibuf;
	char			 buf[32];
	int			 n;

	if (event & EV_WRITE) {
		if (imsgbuf_write(&s->store_iev->ibuf) == -1) {
			log_warn("session %u: imsgbuf_write (store)", s->id);
			session_teardown(s, "io-error");
		}
	}

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&s->store_iev->ibuf)) == -1) {
			log_warn("session %u: imsgbuf_read (store)", s->id);
			session_teardown(s, "io-error");
		}
		if (n == 0) {
			log_warnx("session %u: store closed channel", s->id);
			session_teardown(s, "io-error");
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&s->store_iev->ibuf, &imsg)) == -1) {
			log_warnx("session %u: imsg_get (store)", s->id);
			session_teardown(s, "io-error");
		}
		if (n == 0)
			break;

		switch (imsg_get_type(&imsg)) {
		case IMSG_MBOX_SELECTED:
			if (recv_fixed(&imsg, &u.selected, sizeof(u.selected),
			    "IMSG_MBOX_SELECTED"))
				session_handle_mbox_selected(s, &u.selected);
			break;
		case IMSG_MBOX_STATUS_RESULT:
			if (recv_fixed(&imsg, &u.status, sizeof(u.status),
			    "IMSG_MBOX_STATUS_RESULT"))
				session_handle_mbox_status_result(s, &u.status);
			break;
		case IMSG_MBOX_FETCH_HEADER:
			if (recv_header(&imsg, &ibuf, &u.header,
			    sizeof(u.header), "IMSG_MBOX_FETCH_HEADER"))
				fetch_part_recv(s, &ibuf,
				    "IMSG_MBOX_FETCH_HEADER", u.header.found,
				    u.header.hdrlen, &s->cmd.pending_header_buf,
				    &s->cmd.pending_header_len,
				    &s->cmd.pending_header_found);
			break;
		case IMSG_MBOX_FETCH_BODY:
			session_recv_fetch_body(s, &imsg);
			break;
		case IMSG_MBOX_FETCH_ENVELOPE:
			if (recv_header(&imsg, &ibuf, &u.envelope,
			    sizeof(u.envelope), "IMSG_MBOX_FETCH_ENVELOPE"))
				fetch_part_recv(s, &ibuf,
				    "IMSG_MBOX_FETCH_ENVELOPE",
				    u.envelope.found, u.envelope.envlen,
				    &s->cmd.pending_envelope_buf,
				    &s->cmd.pending_envelope_len,
				    &s->cmd.pending_envelope_found);
			break;
		case IMSG_MBOX_FETCH_BODYSTRUCTURE:
			if (recv_header(&imsg, &ibuf, &u.bodystructure,
			    sizeof(u.bodystructure),
			    "IMSG_MBOX_FETCH_BODYSTRUCTURE"))
				fetch_part_recv(s, &ibuf,
				    "IMSG_MBOX_FETCH_BODYSTRUCTURE",
				    u.bodystructure.found,
				    u.bodystructure.bslen,
				    &s->cmd.pending_bodystructure_buf,
				    &s->cmd.pending_bodystructure_len,
				    &s->cmd.pending_bodystructure_found);
			break;
		case IMSG_MBOX_FETCH_META:
			if (!recv_fixed(&imsg, &u.meta, sizeof(u.meta),
			    "IMSG_MBOX_FETCH_META"))
				break;
			u.meta.flags[sizeof(u.meta.flags) - 1] = '\0';
			/* While selecting, buffer to keep the QRESYNC order. */
			if (s->state == SESSION_SELECTING)
				session_handle_select_fetch(s, &u.meta);
			else if (s->state == SESSION_STORING)
				session_send_store_fetch_response(s, &u.meta);
			else
				session_send_fetch_response(s, &u.meta);
			break;
		case IMSG_MBOX_EXPUNGED:
			if (!recv_fixed(&imsg, &u.expunged, sizeof(u.expunged),
			    "IMSG_MBOX_EXPUNGED"))
				break;
			if (s->state == SESSION_COPYING)
				session_hold_expunged(s, &u.expunged);
			else
				session_send_expunge_response(s, &u.expunged);
			break;
		case IMSG_MBOX_COPY_MAPPING:
			if (recv_fixed(&imsg, &u.mapping, sizeof(u.mapping),
			    "IMSG_MBOX_COPY_MAPPING"))
				session_handle_mbox_copy_mapping(s, &u.mapping);
			break;
		case IMSG_MBOX_SEARCH_MATCH:
			if (recv_fixed(&imsg, &u.match, sizeof(u.match),
			    "IMSG_MBOX_SEARCH_MATCH"))
				session_handle_mbox_search_match(s, &u.match);
			break;
		case IMSG_MBOX_SELECT_VANISHED:
			if (!recv_fixed(&imsg, &u.vanished, sizeof(u.vanished),
			    "IMSG_MBOX_SELECT_VANISHED"))
				break;
			if (s->state == SESSION_SELECTING)
				session_handle_select_vanished(s, &u.vanished);
			else
				session_handle_fetch_vanished(s, &u.vanished);
			break;
		case IMSG_MBOX_STORE_MODIFIED:
			if (recv_fixed(&imsg, &u.modified, sizeof(u.modified),
			    "IMSG_MBOX_STORE_MODIFIED"))
				session_handle_store_modified(s, &u.modified);
			break;
		case IMSG_MBOX_VIEW_EXPUNGE:
			if (recv_fixed(&imsg, &u.expunged, sizeof(u.expunged),
			    "IMSG_MBOX_VIEW_EXPUNGE"))
				session_send_expunge_response(s, &u.expunged);
			break;
		case IMSG_MBOX_VIEW_FETCH:
			if (!recv_fixed(&imsg, &u.meta, sizeof(u.meta),
			    "IMSG_MBOX_VIEW_FETCH"))
				break;
			u.meta.flags[sizeof(u.meta.flags) - 1] = '\0';
			session_handle_view_fetch(s, &u.meta);
			break;
		case IMSG_MBOX_VIEW_EXISTS:
			if (!recv_fixed(&imsg, &u.exists, sizeof(u.exists),
			    "IMSG_MBOX_VIEW_EXISTS"))
				break;
			snprintf(buf, sizeof(buf), "%u EXISTS",
			    u.exists.exists);
			session_untagged(s, buf);
			break;
		case IMSG_MBOX_IDLE_REFRESHED:
			if (recv_fixed(&imsg, &u.refreshed, sizeof(u.refreshed),
			    "IMSG_MBOX_IDLE_REFRESHED"))
				session_handle_idle_refreshed(s, &u.refreshed);
			break;
		case IMSG_MBOX_RESULT:
			if (recv_fixed(&imsg, &u.result, sizeof(u.result),
			    "IMSG_MBOX_RESULT"))
				session_handle_mbox_result(s, &u.result);
			break;
		case IMSG_MBOX_LIST_ITEM:
			if (!recv_fixed(&imsg, &u.item, sizeof(u.item),
			    "IMSG_MBOX_LIST_ITEM"))
				break;
			u.item.mailbox[sizeof(u.item.mailbox) - 1] = '\0';
			session_handle_mbox_list_item(s, &u.item);
			break;
		case IMSG_MBOX_APPENDED:
			if (recv_fixed(&imsg, &u.appended, sizeof(u.appended),
			    "IMSG_MBOX_APPENDED"))
				session_handle_mbox_appended(s, &u.appended);
			break;
		default:
			log_debug("session %u: store channel: unhandled %d",
			    s->id, imsg_get_type(&imsg));
			break;
		}
		imsg_free(&imsg);
	}
	imsgev_rearm_read(s->store_iev);

	session_dequeue_next(s);
}

/*
 * Under QRESYNC, VANISHED precedes FETCH, then the tagged OK.
 */
static void
session_handle_mbox_selected(struct session *s,
    const struct imsg_mbox_selected *res)
{
	uint32_t	 i;
	size_t		 qlen = 0, vlen;
	char		 buf[128], vbuf[8192], full[8192 + 32];
	char		 qname[MBOX_QUOTED_MAX];
	char		 listbuf[MBOX_QUOTED_MAX + 64];
	int		 truncated, flen;

	if (res->error != MBOX_OP_OK || s->cmd.qresync_alloc_failed) {
		s->state = SESSION_AUTHENTICATED;
		session_reply(s, s->cmd.pending_tag, "NO",
		    s->cmd.qresync_alloc_failed ?
		    "[UNAVAILABLE] SELECT failed" :
		    mbox_error_text(res->error, s->mbox_readonly ? "EXAMINE" :
		    "SELECT", buf, sizeof(buf)));
		return;
	}

	s->state = SESSION_SELECTED;
	s->mbox_highestmodseq = res->highestmodseq;

	snprintf(buf, sizeof(buf), "%u EXISTS", res->exists);
	session_untagged(s, buf);

	snprintf(buf, sizeof(buf), "OK [UIDVALIDITY %u] UIDs valid",
	    res->uidvalidity);
	session_untagged(s, buf);

	snprintf(buf, sizeof(buf), "OK [UIDNEXT %u] predicted next UID",
	    res->uidnext);
	session_untagged(s, buf);

	if (s->condstore_enabled) {
		snprintf(buf, sizeof(buf), "OK [HIGHESTMODSEQ %llu]",
		    (unsigned long long)res->highestmodseq);
		session_untagged(s, buf);
	}

	/* EXAMINE gets no PERMANENTFLAGS. */
	session_untagged(s,
	    "FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
	if (s->mbox_readonly)
		session_untagged(s,
		    "OK [PERMANENTFLAGS ()] no permanent flags");
	else
		session_untagged(s,
		    "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen "
		    "\\Draft \\*)] system flags and keywords allowed");

	if (quote_mailbox(qname, sizeof(qname), s->selected_mailbox) == -1)
		log_warnx("session %u: SELECT LIST mailbox name truncated",
		    s->id);
	line_append(listbuf, sizeof(listbuf), &qlen,
	    "* LIST () \"/\" %s\r\n", qname);
	session_write(s, listbuf, qlen);

	if (s->cmd.vanished_nranges > 0) {
		vlen = format_range_list(vbuf, sizeof(vbuf),
		    s->cmd.vanished_ranges, s->cmd.vanished_nranges,
		    &truncated);
		if (truncated)
			log_warnx("session %u: VANISHED (EARLIER) list "
			    "truncated at %zu bytes", s->id, vlen);

		flen = snprintf(full, sizeof(full),
		    "* VANISHED (EARLIER) %s\r\n",
		    vbuf);
		if (flen > 0)
			session_write(s, full, (size_t)flen >= sizeof(full) ?
			    sizeof(full) - 1 : (size_t)flen);
	}

	for (i = 0; i < s->cmd.qresync_nfetches; i++)
		session_send_qresync_fetch_response(s,
		    &s->cmd.qresync_fetches[i]);

	if (s->mbox_readonly)
		session_reply(s, s->cmd.pending_tag, "OK",
		    "[READ-ONLY] EXAMINE completed");
	else
		session_reply(s, s->cmd.pending_tag, "OK",
		    "[READ-WRITE] SELECT completed");
}

/*
 * Attributes go out in a fixed order.
 */
static void
session_handle_mbox_status_result(struct session *s,
    const struct imsg_mbox_status_result *res)
{
	char	qname[MBOX_QUOTED_MAX];
	/* The quoted name plus the attributes. */
	char	buf[MBOX_QUOTED_MAX + 384];
	size_t	len = 0;
	int	first = 1;

	s->state = s->cmd.status_prev_state;

	if (res->error != MBOX_OP_OK) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    mbox_error_text(res->error, "STATUS", buf, sizeof(buf)));
		return;
	}

	if (quote_mailbox(qname, sizeof(qname), s->cmd.status_mailbox) == -1)
		log_warnx("session %u: STATUS mailbox name truncated", s->id);
	line_append(buf, sizeof(buf), &len, "* STATUS %s (", qname);

#define STATUS_APPEND(fmt, val) do {					\
	line_append(buf, sizeof(buf), &len, "%s" fmt,			\
	    first ? "" : " ", (val));					\
	first = 0;							\
} while (0)

	if (s->cmd.status_attrs & STATUS_ATT_MESSAGES)
		STATUS_APPEND("MESSAGES %u", res->messages);
	if (s->cmd.status_attrs & STATUS_ATT_RECENT)
		/* IMAP4rev2 has no \Recent, so always 0. */
		STATUS_APPEND("RECENT %u", 0U);
	if (s->cmd.status_attrs & STATUS_ATT_UIDNEXT)
		STATUS_APPEND("UIDNEXT %u", res->uidnext);
	if (s->cmd.status_attrs & STATUS_ATT_UIDVALIDITY)
		STATUS_APPEND("UIDVALIDITY %u", res->uidvalidity);
	if (s->cmd.status_attrs & STATUS_ATT_UNSEEN)
		STATUS_APPEND("UNSEEN %u", res->unseen);
	if (s->cmd.status_attrs & STATUS_ATT_DELETED)
		STATUS_APPEND("DELETED %u", res->deleted);
	if (s->cmd.status_attrs & STATUS_ATT_SIZE)
		STATUS_APPEND("SIZE %llu", (unsigned long long)res->size);
	if (s->cmd.status_attrs & STATUS_ATT_HIGHESTMODSEQ)
		STATUS_APPEND("HIGHESTMODSEQ %llu",
		    (unsigned long long)res->highestmodseq);

#undef STATUS_APPEND

	line_append(buf, sizeof(buf), &len, ")\r\n");
	session_write(s, buf, len);
	session_reply(s, s->cmd.pending_tag, "OK", "STATUS completed");
}

static void
session_finish_mbox_op(struct session *s, const struct imsg_mbox_result *res)
{
	const char	*cmdname;
	char		 text[64];

	if (s->state == SESSION_CREATING)
		cmdname = "CREATE";
	else if (s->state == SESSION_DELETING)
		cmdname = "DELETE";
	else if (s->state == SESSION_SUBSCRIBING)
		cmdname = "SUBSCRIBE";
	else if (s->state == SESSION_UNSUBSCRIBING)
		cmdname = "UNSUBSCRIBE";
	else
		cmdname = "RENAME";

	s->state = s->cmd.mbox_op_prev_state;

	if (res->error != MBOX_OP_OK) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    mbox_error_text(res->error, cmdname, text, sizeof(text)));
		return;
	}

	/* The selection follows a RENAME. */
	if (s->state == SESSION_SELECTED &&
	    strcmp(s->selected_mailbox, s->cmd.mbox_op_name) == 0) {
		if (strcmp(cmdname, "RENAME") == 0) {
			strlcpy(s->selected_mailbox, s->cmd.rename_newname,
			    sizeof(s->selected_mailbox));
		} else if (strcmp(cmdname, "DELETE") == 0) {
			/* The mailbox is gone, so deselect. */
			s->state = SESSION_AUTHENTICATED;
			s->selected_mailbox[0] = '\0';
		}
	}

	snprintf(text, sizeof(text), "%s completed", cmdname);
	session_reply(s, s->cmd.pending_tag, "OK", text);
}

static void
session_handle_mbox_list_item(struct session *s,
    const struct imsg_mbox_list_item *item)
{
	const char	*kw = s->cmd.list_is_lsub ? "LSUB" : "LIST";
	const char	*attrs;
	size_t		 len = 0;
	char		 qname[MBOX_QUOTED_MAX];
	char		 buf[MBOX_QUOTED_MAX + 64];

	if (!list_pattern_match(s->cmd.list_pattern, item->mailbox, 0))
		return;

	if (!s->cmd.list_subscribed_only)
		attrs = "";
	else if (s->cmd.list_is_lsub)
		attrs = item->exists ? "" : "\\Noselect";
	else
		attrs = item->exists ? "\\Subscribed" :
		    "\\Subscribed \\NonExistent";

	if (quote_mailbox(qname, sizeof(qname), item->mailbox) == -1)
		log_warnx("session %u: LIST mailbox name truncated", s->id);
	line_append(buf, sizeof(buf), &len, "* %s (%s) \"/\" %s\r\n",
	    kw, attrs, qname);
	session_write(s, buf, len);
}

static void
session_finish_list(struct session *s, const struct imsg_mbox_result *res)
{
	const char	*cmdname = s->cmd.list_is_lsub ? "LSUB" : "LIST";
	char		 text[32];

	s->state = s->cmd.mbox_op_prev_state;

	if (res->error != MBOX_OP_OK) {
		snprintf(text, sizeof(text), "%s failed", cmdname);
		session_reply(s, s->cmd.pending_tag, "NO", text);
		return;
	}

	snprintf(text, sizeof(text), "%s completed", cmdname);
	session_reply(s, s->cmd.pending_tag, "OK", text);
}

static void
session_handle_mbox_copy_mapping(struct session *s,
    const struct imsg_mbox_copy_mapping *m)
{
	uint32_t	 newcap, *newsrc, *newdest;

	if (s->cmd.copy_alloc_failed)
		return;

	if (s->cmd.copy_n == s->cmd.copy_cap) {
		newcap = s->cmd.copy_cap ? s->cmd.copy_cap * 2 : 16;

		newsrc = reallocarray(s->cmd.copy_src_uids, newcap,
		    sizeof(uint32_t));
		if (newsrc == NULL) {
			log_warn("session %u: realloc COPY src array", s->id);
			s->cmd.copy_alloc_failed = 1;
			return;
		}
		s->cmd.copy_src_uids = newsrc;

		newdest = reallocarray(s->cmd.copy_dest_uids, newcap,
		    sizeof(uint32_t));
		if (newdest == NULL) {
			log_warn("session %u: realloc COPY dest array", s->id);
			s->cmd.copy_alloc_failed = 1;
			return;
		}
		s->cmd.copy_dest_uids = newdest;
		s->cmd.copy_cap = newcap;
	}

	s->cmd.copy_src_uids[s->cmd.copy_n] = m->src_uid;
	s->cmd.copy_dest_uids[s->cmd.copy_n] = m->dest_uid;
	s->cmd.copy_n++;
}

/*
 * A dropped range would hide a UID for ever.
 */
static void
session_handle_select_vanished(struct session *s,
    const struct imsg_mbox_select_vanished *v)
{
	struct vanished_range	*n;
	uint32_t		 newcap;

	if (s->cmd.vanished_nranges == s->cmd.vanished_cap) {
		newcap = s->cmd.vanished_cap ?
		    s->cmd.vanished_cap * 2 : 16;

		n = reallocarray(s->cmd.vanished_ranges, newcap, sizeof(*n));
		if (n == NULL) {
			log_warn("session %u: realloc VANISHED range array",
			    s->id);
			s->cmd.qresync_alloc_failed = 1;
			return;
		}
		s->cmd.vanished_ranges = n;
		s->cmd.vanished_cap = newcap;
	}

	s->cmd.vanished_ranges[s->cmd.vanished_nranges].lo = v->uid_lo;
	s->cmd.vanished_ranges[s->cmd.vanished_nranges].hi = v->uid_hi;
	s->cmd.vanished_nranges++;
}

static void
session_handle_select_fetch(struct session *s,
    const struct imsg_mbox_fetch_meta *m)
{
	struct imsg_mbox_fetch_meta	*n;
	uint32_t			 newcap;

	if (s->cmd.qresync_nfetches == s->cmd.qresync_fetches_cap) {
		newcap =
		    s->cmd.qresync_fetches_cap ?
		    s->cmd.qresync_fetches_cap * 2 : 16;

		n = reallocarray(s->cmd.qresync_fetches, newcap, sizeof(*n));
		if (n == NULL) {
			log_warn("session %u: realloc QRESYNC fetch array",
			    s->id);
			s->cmd.qresync_alloc_failed = 1;
			return;
		}
		s->cmd.qresync_fetches = n;
		s->cmd.qresync_fetches_cap = newcap;
	}

	s->cmd.qresync_fetches[s->cmd.qresync_nfetches++] = *m;
}

/*
 * An unsolicited FETCH carries the UID.
 */
static void
session_handle_view_fetch(struct session *s,
    const struct imsg_mbox_fetch_meta *meta)
{
	char	buf[MBOX_FLAGS_MAX + 96];

	if (s->condstore_enabled)
		snprintf(buf, sizeof(buf),
		    "%u FETCH (UID %u FLAGS (%s) MODSEQ (%llu))", meta->seqno,
		    meta->uid, meta->flags, (unsigned long long)meta->modseq);
	else
		snprintf(buf, sizeof(buf), "%u FETCH (UID %u FLAGS (%s))",
		    meta->seqno, meta->uid, meta->flags);
	session_untagged(s, buf);
}

static void
session_handle_idle_refreshed(struct session *s,
    const struct imsg_mbox_idle_refreshed *res)
{
	s->idle_refresh_pending = 0;

	if (!res->ok && res->busy)
		log_debug("session %u: IDLE refresh skipped, index lock busy",
		    s->id);
	else if (!res->ok)
		log_warnx("session %u: IDLE refresh failed, keeping last "
		    "known state", s->id);

	if (s->cmd.refresh_status != NULL) {
		session_reply(s, s->cmd.pending_tag, s->cmd.refresh_status,
		    s->cmd.refresh_text);
		s->cmd.refresh_status = NULL;
	} else if (s->idle_refresh_again && s->idling) {
		s->idle_refresh_again = 0;
		(void)session_request_idle_refresh(s);
	}
}

int
session_request_idle_refresh(struct session *s)
{
	if (s->idle_refresh_pending) {
		s->idle_refresh_again = 1;
		return (0);
	}
	if (imsg_compose(&s->store_iev->ibuf, IMSG_MBOX_IDLE_REFRESH, 0, 0,
	    -1, NULL, 0) == -1) {
		log_warn("session %u: imsg_compose IMSG_MBOX_IDLE_REFRESH",
		    s->id);
		return (-1);
	}
	s->idle_refresh_pending = 1;
	return (0);
}

static void
session_idle_poll(int fd, short event, void *arg)
{
	struct session	*s = arg;

	if (!s->idling || s->state != SESSION_SELECTED) {
		log_debug("session %u: idle poll while not idling (idling=%d "
		    "state=%d)", s->id, s->idling, (int)s->state);
		return;
	}

	(void)session_request_idle_refresh(s);
	session_idle_poll_arm(s);	/* An evtimer is one-shot. */
}

void
session_idle_poll_init(struct session *s)
{
	evtimer_set(&s->idle_ev, session_idle_poll, s);
}

void
session_idle_poll_arm(struct session *s)
{
	struct timeval	 tv;

	if (listener_idle_poll_secs == 0)
		return;

	tv.tv_sec = (time_t)listener_idle_poll_secs;
	tv.tv_usec = 0;
	if (evtimer_add(&s->idle_ev, &tv) == -1)
		log_warnx("session %u: evtimer_add (idle poll)", s->id);
}

void
session_idle_poll_disarm(struct session *s)
{
	evtimer_del(&s->idle_ev);
}

/*
 * Always UID, FLAGS and MODSEQ.
 */
static void
session_send_qresync_fetch_response(struct session *s,
    const struct imsg_mbox_fetch_meta *meta)
{
	char	buf[MBOX_FLAGS_MAX + 96];

	snprintf(buf, sizeof(buf), "%u FETCH (UID %u FLAGS (%s) MODSEQ (%llu))",
	    meta->seqno, meta->uid, meta->flags,
	    (unsigned long long)meta->modseq);
	session_untagged(s, buf);
}

/* Worst-case sizes for a MODIFIED response code. */
#define MODIFIED_PER_ENTRY	11
#define MODIFIED_WRAPPER_MAX	160

static void
session_handle_mbox_result(struct session *s, struct imsg_mbox_result *res)
{
	const char	*cmdname;
	size_t		 rbufsize, textsize;
	char		 reply[96], *rbuf, *text, fail[64];
	int		 was_close = 0, was_storing = 0, was_expunging = 0, n;
	int		 truncated, incomplete;

	if (s->state == SESSION_SEARCHING) {
		session_finish_search(s, res);
		return;
	}
	if (s->state == SESSION_COPYING) {
		session_finish_copy_or_move(s, res);
		return;
	}
	if (s->state == SESSION_CREATING || s->state == SESSION_DELETING ||
	    s->state == SESSION_RENAMING || s->state == SESSION_SUBSCRIBING ||
	    s->state == SESSION_UNSUBSCRIBING) {
		session_finish_mbox_op(s, res);
		return;
	}
	if (s->state == SESSION_LISTING) {
		session_finish_list(s, res);
		return;
	}

	if (s->state == SESSION_STORING) {
		cmdname = s->cmd.cmd_by_uid ? "UID STORE" : "STORE";
		was_storing = 1;
	} else if (s->state == SESSION_EXPUNGING) {
		was_close = s->cmd.close_after_expunge;
		cmdname = was_close ? "CLOSE" :
		    (s->cmd.cmd_by_uid ? "UID EXPUNGE" : "EXPUNGE");
		was_expunging = 1;
	} else
		cmdname = s->cmd.cmd_by_uid ? "UID FETCH" : "FETCH";

	log_debug("session %u: %s done, status=%s, %u response(s) sent",
	    s->id, cmdname, res->error == MBOX_OP_OK ? "OK" : "ERROR",
	    res->count);

	/* Only a successful CLOSE deselects. */
	s->state = (was_close && res->error == MBOX_OP_OK) ?
	    SESSION_AUTHENTICATED : SESSION_SELECTED;

	if (res->error != MBOX_OP_OK) {
		session_reply(s, s->cmd.pending_tag, "NO",
		    mbox_error_text(res->error, cmdname, reply, sizeof(reply)));
		return;
	}

	if (was_storing || was_expunging)
		s->mbox_highestmodseq = res->highestmodseq;

	if (was_storing && (s->cmd.store_modified_n > 0 ||
	    s->cmd.store_modified_alloc_failed)) {
		rbuf = NULL;
		text = NULL;

		incomplete = s->cmd.store_modified_alloc_failed;

		rbufsize = (size_t)s->cmd.store_modified_n *
		    MODIFIED_PER_ENTRY + 1;
		textsize = rbufsize + MODIFIED_WRAPPER_MAX;

		if (!incomplete) {
			if ((rbuf = malloc(rbufsize)) != NULL &&
			    (text = malloc(textsize)) != NULL) {
				format_seq_list(rbuf, rbufsize,
				    s->cmd.store_modified,
				    s->cmd.store_modified_n, &truncated);
				if (truncated) {
					log_warnx("session %u: MODIFIED list "
					    "truncated", s->id);
					incomplete = 1;
				} else {
					n = snprintf(text, textsize,
					    "%s OK [MODIFIED %s] Conditional "
					    "%s failed for some messages\r\n",
					    s->cmd.pending_tag, rbuf, cmdname);
					if (n < 0 || (size_t)n >= textsize) {
						log_warnx("session %u: MODIFIED"
						    " response text truncated",
						    s->id);
						incomplete = 1;
					} else
						session_write(s, text,
						    (size_t)n);
				}
			} else {
				log_warn("session %u: malloc MODIFIED response",
				    s->id);
				incomplete = 1;
			}
		}

		free(rbuf);
		free(text);

		/* An incomplete MODIFIED fails the command. */
		if (incomplete) {
			snprintf(fail, sizeof(fail), "[UNAVAILABLE] %s failed",
			    cmdname);
			session_reply(s, s->cmd.pending_tag, "NO", fail);
		}
		return;
	}

	/* No HIGHESTMODSEQ on CLOSE, RFC 7162 section 3.2.8. */
	if (was_expunging && !was_close && s->condstore_enabled &&
	    res->count > 0) {
		snprintf(reply, sizeof(reply), "[HIGHESTMODSEQ %llu] %s "
		    "completed", (unsigned long long)res->highestmodseq,
		    cmdname);
		session_reply(s, s->cmd.pending_tag, "OK", reply);
		return;
	}

	if (s->cmd.fetch_incomplete) {
		snprintf(reply, sizeof(reply),
		    "%s failed, some requested items could not be returned",
		    cmdname);
		session_reply(s, s->cmd.pending_tag, "NO", reply);
		return;
	}

	snprintf(reply, sizeof(reply), "%s completed", cmdname);
	session_reply(s, s->cmd.pending_tag, "OK", reply);
}
