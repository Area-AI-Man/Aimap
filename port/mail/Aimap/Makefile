COMMENT =	privilege-separated IMAP4rev2 server written by Claude AI

VERSION =	0.0.1
DISTNAME =	aimap-${VERSION}

CATEGORIES =	mail

HOMEPAGE =	https://github.com/Area-AI-Man/Aimap

MAINTAINER =	Area AI Man <serried_lapdogs_9r@icloud.com>

# ISC and 2-clause BSD for third-party portions (see CREDITS);
# all other code is AI-generated and not copyrightable under U.S. law
PERMIT_PACKAGE =	Yes

# uses pledge()
WANTLIB =	c crypto event ssl tls util

SITES =		https://github.com/Area-AI-Man/Aimap/releases/download/v${VERSION}/

WRKSRC =	${WRKDIST}/src

FAKE_FLAGS =	BINDIR=${TRUEPREFIX}/sbin MANDIR=${TRUEPREFIX}/man/man \
		EXAMPLEDIR=${TRUEPREFIX}/share/examples/aimap

NO_TEST =	Yes

.include <bsd.port.mk>
