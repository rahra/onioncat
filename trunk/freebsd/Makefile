# New ports collection makefile for: onioncat
# Date created:        2 March 2009
# Whom:                Bernhard R. Fischer
#
# $FreeBSD$
#

PORTNAME=      onioncat
PORTVERSION=   0.1.12.r487
CATEGORIES=    security
MASTER_SITES=  http://www.cypherpunk.at/ocat/download/

MAINTAINER=    bf@abenteuerland.at
COMMENT=       A world wide IPv6 VPN based on Tor

MAN1=          ocat.1
MANCOMPRESSED= no
GNU_CONFIGURE= yes
RUN_DEPENDS=   ${LOCALBASE}/bin/tor:${PORTSDIR}/security/tor
OPTIONS=       DEBUG "Enable debug output" Off \
               CHECK_IPSRC "disable source ip checking before forwarding" Off

.include <bsd.port.pre.mk>

.if defined(WITH_DEBUG)
CONFIGURE_ARGS+=    --enable-debug
.else
CONFIGURE_ARGS+=    --disable-debug
.endif

.if defined(WITH_CHECK_IPSRC)
CONFIGURE_ARGS+=    --enable-check-ipsrc
.else
CONFIGURE_ARGS+=    --disable-check-ipsrc
.endif

.include <bsd.port.post.mk>
