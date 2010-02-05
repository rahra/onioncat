# ports collection makefile for:	onioncat
# Date created:				2 March 2009
# Whom:					Bernhard R. Fischer, 2048R/5C5FFD47 <bf@abenteuerland.at>
#
# $FreeBSD$
#

PORTNAME=	onioncat
PORTVERSION=	0.1.12.r493
CATEGORIES=	security
MASTER_SITES=	http://www.cypherpunk.at/ocat/download/

MAINTAINER=	bf@abenteuerland.at
COMMENT=	A world wide IPv6 VPN based on Tor

RUN_DEPENDS=	tor:${PORTSDIR}/security/tor

GNU_CONFIGURE=	yes
OPTIONS=	DEBUG "Enable debug output" Off \
		CHECK_IPSRC "disable source ip checking before forwarding" Off

MAN1=		ocat.1
MANCOMPRESSED=	no

.include <bsd.port.pre.mk>

.if defined(WITH_DEBUG)
CONFIGURE_ARGS+=	--enable-debug
.else
CONFIGURE_ARGS+=	--disable-debug
.endif

.if defined(WITH_CHECK_IPSRC)
CONFIGURE_ARGS+=	--enable-check-ipsrc
.else
CONFIGURE_ARGS+=	--disable-check-ipsrc
.endif

.include <bsd.port.post.mk>
