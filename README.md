# ocat(1) - OnionCat creates a transparent IPv6 layer on top of Tor's or I2P hidden

ocat, 2020-05-15

services.

<a name="synopsis"></a>

# Synopsis

```
ocat -i onion_id                      (1st form)
ocat -o IPv6_address                  (2nd form)
ocat [OPTION] onion_id                (3rd form)
ocat -R [OPTION]                      (4th form)
ocat -I [OPTION] i2p_id                  (5th form)

```

<a name="description"></a>

# Description

OnionCat creates a transparent IPv6 layer on top of Tor's hidden services or
I2P's tunnels. It transmits any kind of IP-based data transparently through the
Tor/I2P network on a location hidden basis. You can think of it as a
peer-to-peer VPN between hidden services.

OnionCat is a stand-alone application which runs in userland and is a connector
between Tor/I2P and the local OS. Any protocol which is based on IP can be
transmitted. Of course, UDP and TCP (and probably ICMP) are the most important
ones but all other protocols can also be forwarded through it.

OnionCat opens a TUN device and assigns an IPv6 address to it. All packets
forwarded to the TUN device by the kernel are forwarded by OnionCat to other
OnionCats listening on Tor's hidden service ports or I2P's server tunnels. The
IPv6 address depends on the _onion\_id_ or the i2p_id, respectively. The
_onion\_id_ is the hostname of the locally configured hidden service (see
**tor(8)**). Depending on the configuration of Tor the _onion\_id_ usually
can be found at _/var/lib/tor/hidden\_service/hostname_ or similar location.
The _i2p\_id_ is the 80 bit long Base32 encoded hostname of the I2P server
tunnel.

OnionCat has two implemented loopback responders for easier network debugging.
Ping responses from loopback address fd87:d87e:eb43::dead:beef indicate correct
network setup between the kernel and OnionCat.
Ping responses from fd87:d87e:eb43::feed:beef indicate that connection between
OnionCat and Tor itself works, hidden service correctly configured and enabled.


<a name="options"></a>

### OPTIONS


* **-4**  
  Enable IPv4 forwarding. See http://www.cypherpunk.at/onioncat_trac/wiki/IPv4  
  IPv4-througth-IPv6 tunnel through OnionCat is recommended instead of using native
  IPv4 forwarding.
* **-5** _'socks5'|'direct'_  
  This option has a mandatory argument which is literally either _socks5_ or
  _direct_.  
  By default OnionCat uses SOCKS4A (version 4a) to connect to the anonymization
  network proxy (e.g. Tor). With this option set to _socks5_, OnionCat uses
  SOCKS5 (version 5 as specified in RFC1928), currently with no authentication
  mechanism. As of today it actually makes no difference but it might be
  desireable in future.  
  If _direct_ is used, OnionCat does not connect through to SOCKS server but
  instead it connects directly to the remote peers using the hosts lookup
  mechanism (see option **-H**).
  This feature is experimental and turns OnionCat into a distributed virtual switch
  based on regular Internet transport instead of Tor. It is useful feature for lab
  setup.
* **-a**  
  OnionCat creates a log file at $HOME/.ocat/connect_log. All incoming connects are
  logged to that file. $HOME is determined from the user under which OnionCat runs
  (see option -u).
* **-b**  
  Run OnionCat in background. This is default. OnionCat will detach from a running
  shell and close standard IO if no log file is given with option -L.
* **-B**  
  Run OnionCat in foreground. OnionCat will log to stderr by default.
* **-C**  
  Disable the local controller interface. The controller interfaces listens on
  localhost (127.0.0.1 and ::1 port 8066) for incoming connections. It's
  currently used for debugging purpose and not thread-safe and does not have any
  kind of authentication or authorization mechanism. Hence, it should not be used
  in production environments.
* **-d** _n_  
  Set debug level to _n_. Default = 7 which is maximum. Debug output will
  only be created if OnionCat was compiled with option DEBUG (i.e. configure was
  run with option --enable-debug).
* **-e** _ifup_  
  Execute script _ifup_ to bring up the tunnel interface.  
  OnionCat will create a new tunnel interface and execute _ifup_ immediatly
  after opening the network interface. This is intended as a universial interface
  for configuring the tunnel device and do additinal tasks when starting
  OnionCat.  The script is executed with the same privilege as OnionCat is
  started, i.e. before dropping privileges. This typically is root. The script is
  run only once at startup.
  
  See below in section EXAMPLES for a typical Linux ifup shell script.
  
  OnionCat executes the file _ifup_ with a call to execlp(3) and will pass
  the following environment variables: 
  
  **OCAT\_IFNAME**  
  This variable contains the name of the network interface, e.g. "tun0".
   
  **OCAT\_ADDRESS**  
  This variable contains the IPv6 address which is associated with this instance
  of OnionCat and its hidden service address.
  
  **OCAT\_PREFIXLEN**  
  This variable contains the prefix length of the IPv6 prefix which typically is
  48.
  
  **OCAT\_PREFIX**  
  This variable contains the IPv6 prefix, i.e. the network. This typically is
  fd87:d87e:eb43:: in OnionCat (Tor) mode and fd60:db4d:ddb5:: in GarliCat
  (I2P) mode.
  
  **OCAT\_ONION\_URL**  
  This variable contains the short onion URL without domain appendix. It is a
  16 character long string.
  
  **OCAT\_ONION3\_URL**  
  This variable contains the long onion URL if available which is always true for
  I2P and in case of Tor it is used together with the HSv3 variant.
  
  **OCAT\_DOMAIN**  
  This variable contains the TLD appendix which is .onion for Tor and .b32.i2p
  for I2P.
  
* **-f** _config file_  
  Read initial configuration from _config file_. 
* **-g** _hosts\_path_  
  Set the path to the hosts file. This option automatically enables option -H
  (see there). If -g is not set, the path defaults to the system hosts file
  which typically is /etc/hosts on Un*x systems.
* **-H**  
  This option enables the hosts reverse lookup. If OnionCat receives a packet to
  a destination IPv6 address within the OnionCat prefix, it translates it
  directly to a .onion hostname by default. If option -H is enabled, OnionCat
  instead looks up the hostname in the hosts file (see also -g). This option is
  always enabled when OnionCat is used in GarliCat mode for I2P and it is required
  with V3 hidden services of Tor (see below).
* **-h**  
  Display short usage message and shows options.
* **-i**  
  Convert _onion\_id_ to IPv6 address and exit.
* **-I**  
  Run OnionCat in GarliCat (I2P) mode.
* **-l** _[ip:]port_  
  Bind OnionCat to specific _ip _ and/or _port_ number for incoming
  connections. It defaults to 127.0.0.1:8060. This option could be set
  multiple times. IPv6 addresses must be given in square brackets.  
  The parameter _"none"_ deactivates the listener completely. This is for
  special purpose only and shall not be used in regular operation.
* **-L** _log\_file_  
  Log output to _log\_file_. If option is omitted, OnionCat logs to syslog if
  running in background or to stderr if running in foreground. If syslogging is
  desired while running in foreground, specify the special file name "syslog" as
  log file.
* **-o** _IPv6 address_  
  Convert _IPv6 address_ to _onion\_id_ and exit program.
* **-p**  
  Use TAP device instead of TUN device. There are a view differences. See TAP
  DEVICE later.
* **-P** _[pid file]_  
  Create _pid file_ at _pid\_file_. If the option parameter is omitted OC
  will create a pid file at **/var/run/ocat.pid**. In the latter case it MUST
  NOT be the last option in the list of options.
* **-r**  
  Run OnionCat as root and do not change user id (see option **-u**).
* **-R**  
  Use this option only if you really know what you do! OnionCat generates a
  random local onion_id. With this option it is not necessary to add a hidden
  service to the Tor configuration file **torrc**.  One might use OnionCat
  services within Tor as usually but it is NOT possible to receive incoming
  connections. If you plan to also receive connections (e.g.  because you provide
  a service or you use software which opens sockets for incoming connections
  like Bitorrent) you MUST configure a hidden service and supply its hostname to
  OnionCat on the command line.
  Please note that this option does only work if the remote OC does not run in
  unidirectional mode which is default since SVN version 555 (see option
  **-U**).
* **-s** _port_  
  Set OnionCat's virtual hidden service port to _port_. This should usually
  not be changed.
* **-t** _(IP|[IP:]port)_  
  Set Tor SOCKS _IP_ and/or _port_. If no _IP_ is specified 127.0.0.1
  will be used, if no _port_ is specified 9050 will be used as defaults. IPv6
  addresses must be escaped by square brackets.  
  The special parameter _"none"_ disables OnionCat from making outbound
  connections. This shall be used only in special test scenarios.
* **-T** _tun\_dev_  
  TUN device file to open for creation of TUN interface. It defaults to
  /dev/net/tun on Linux and /dev/tun0 on most other OSes, or /dev/tap0 if TAP
  mode is in use. Setup of a TUN device needs root permissions. OnionCat
  automatically changes userid after the TUN device is set up correctly.
* **-U**  
  Deactivate unidirectional mode. Before SVN version 555 OnionCat ran only in
  bidirectional mode. This is that a connection to another OC was used for
  outgoing _and_ incoming packets. Since this could be a security risk under
  certain conditions, unidirectional mode was implemented in SVN r555 and set to
  default. With this option bidirectional mode can be enabled again. Please note
  that this does not interoperate with option **-R** if the remote OC is
  working in unidirectional mode.
* **-u** _username_  
  _username_ under which OnionCat should run. The uid is changed as soon as
  possible after the tun device setup. If **-u** is omitted, on OpenBSD and
  FreeBSD it tries to use the uid of the user "_tor" which is by default used for
  Tor. On all other systems it tries to get the uid for the user "tor". If it
  does not exists (it calls getpwnam(3)) it defaults to the uid 65534.
  

<a name="tap-device"></a>

### TAP DEVICE

Usually OnionCat opens a TUN device which is a layer 3 interface. With option
**-p** OnionCat opens a TAP device instead which is a virtual ethernet
(layer 2) interface.


<a name="examples"></a>

# Examples

A typical ifup script for OnionCat for a modern Linux distribution using the
\`ip\` command for configuring network related stuff could look like the
following:

.in +3n
    #!/bin/sh
    
    ip address add $OCAT_ADDRESS/$OCAT_PREFIXLEN dev $OCAT_IFNAME
    ip link set $OCAT_IFNAME up 


<a name="onioncat-and-v3-hidden-services"></a>

# Onioncat and V3 Hidden Services

Originially Tor's v2 hidden service addresses had a binary length of 80 bits.
This made it possible to let OnionCat map hidden service addresses to IPv6
addresses and vice versa. The development of OnionCat started in 2008, and this
held for a very long time until recently Tor came up with version 3 of hidden
services. To comply with ongoing development in the field of cryptography the
new hidden service addresses of Tor (since version 0.3.2) are much bigger,
meaning 336 bits. This obviously does not fit into an IPv6 address, hence,
OnionCat is not able any more to translate back and forth between IPv6 and v3
onion addresses.

As a solution OnionCat offers the possibility to do an external hostname lookup
within /etc/hosts instead. Please note that for security reasons, OnionCat
does not use the system resolver, it definitely just reads the local hosts
file. The big drawback for OnionCat is that with v3 hidden services OnionCat
does not work out of the box any more. It requires that the destionations are
configured manually beforehand.

To connect to a v3 hidden service, on the client side add a line to your
/etc/hosts with the IPv6 address and the v3 hostname and run OnionCat with
the additional option **-H**. The hosts entry could look like this (in one
line!):

**fd87:d87e:eb43:45g6:3bbb:9fxf:5877:4319 tulqpcvf7Oeuxzjod6odrpO77ryujc7o0g7kw6c76q9cbnbi7rqskxid.onion**

If this client also has a v3 hidden service, you have to enter its
IPv6/hostname pair to the hosts file on the opposite site as well, except you
use **-U** option.

Please note that you could pick any IPv6 address in this case, although I
suggest to truncate the long hostname just to the last 16 characters for use
with OnionCat, e.g. truncate
"tulqpcvf7Oeuxzjod6odrpO77ryujc7o0g7kw6c76q9cbnbi7rqskxid.onion" to
"6q9cbnbi7rqskxid.onion" and use it as parameter for OnionCat.


<a name="notes"></a>

# Notes

In the versions of OnionCat up to 0.3.7 a symlink named gcat was created.
OnionCat internally handled this as GarliCat which is equal to running ocat
with the option **-I**. The symlink was removed due to a name conflict with a
different binary (see BSD coreutils).


<a name="files"></a>

# Files

$HOME/.ocat/connect_log


<a name="author"></a>

# Author

Concepts, software, and man page written by Bernhard R. Fischer
&lt;[bf@abenteuerland.at](mailto:bf@abenteuerland.at)&gt;. Package maintenance and additional support by Ferdinand
Haselbacher, Daniel Haslinger &lt;[creo-ocat@blackmesa.at](mailto:creo-ocat@blackmesa.at)&gt;, and Wim Gaethofs.


<a name="see-also"></a>

# See Also

OnionCat project page https://www.onioncat.org/

OnionCat source packages are found at https://www.cypherpunk.at/ocat/download/Source/

Tor project homepage https://www.torproject.org/

I2P project homepage https://geti2p.net/


<a name="copyright"></a>

# Copyright

Copyright 2008-2020 Bernhard R. Fischer.

This file is part of OnionCat.

OnionCat is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

OnionCat is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with OnionCat. If not, see &lt;http://www.gnu.org/licenses/&gt;.

