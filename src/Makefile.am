bin_PROGRAMS = ocat
ocat_SOURCES = ocat.c ocatlog.c ocatroute.c ocatthread.c ocattun.c ocatv6conv.c ocatcompat.c ocatpeer.c ocatsetup.c ocatipv4route.c ocateth.c ocatsocks.c ocatlibe.c ocatctrl.c ocatipv6route.c ocaticmp.c ocat_wintuntap.c ocat_netdesc.c ocathosts.c ocatresolv.c ocatfdbuf.c
noinst_HEADERS = ocat.h ocat_netdesc.h strlcpy.c strlcat.c ocathosts.h ocatresolv.h ocatfdbuf.h
oc_statedir = $(localstatedir)/onioncat
AM_CFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\" -DSTATEDIR=\"$(oc_statedir)\"

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(oc_statedir)

