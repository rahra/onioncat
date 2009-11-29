bin_PROGRAMS = ocat
ocat_SOURCES = ocat.c ocatlog.c ocatroute.c ocatthread.c ocattun.c ocatv6conv.c ocatcompat.c ocatpeer.c ocatsetup.c ocatipv4route.c ocateth.c ocatsocks.c ocatlibe.c ocatctrl.c ocatipv6route.c ocaticmp.c ocat_wintuntap.c ocat_netdesc.c
include_HEADERS = ocat.h ocat_netdesc.h strlcpy.c strlcat.c

install-exec-hook:
	$(LN_S) -f $(DESTDIR)$(bindir)/ocat$(EXEEXT) \
	$(DESTDIR)$(bindir)/gcat$(EXEEXT)

