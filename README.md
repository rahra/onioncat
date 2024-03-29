# ocat(1) - OnionCat creates a transparent IPv6 layer on top of Tor's or I2P hidden

ocat, 2023-10-25

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

In the following is a description of all options. Typically you won't need any
of them except specifying your OnionCat's .onion hostname. Depending on your
setup you may use options **-g** and **-A**.

* **-2**  
  This option is here only for simplicity. With this option OnionCat behaves like
  OnionCat3 (version &lt; 0.4.0). Actually it is a short form for using the options
  **-D -H -S**.
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
  If _direct_ is used, OnionCat does not connect through the SOCKS server but
  instead it connects directly to the remote peers using the hosts lookup
  mechanism (see option **-H**).
  This feature is experimental and turns OnionCat into a distributed virtual switch
  based on regular Internet transport instead of Tor. It is a useful feature for
  a lab setup.  
  This option also disables the remote hostname validation (option **-J**).  
  Please note that OnionCat does not implement any encryption technique! It is a
  plain tunneling through TCP sessions.
* **-a**  
  OnionCat creates a log file at $HOME/.ocat/connect_log. All incoming connects are
  logged to that file. $HOME is determined from the user under which OnionCat runs
  (see option -u).
* **-A** [_ipv6_/]_hostname_  
  This option lets you add an IP address hostname pair to the internal hosts db.
  Typically it is enough to specify just the .onion hostname because the IPv6
  address is derived from the hostname. Adding an IP address is either redundant
  or may be used in special scenarios where the IPv6 address differes from its
  original address. The latter will only work in a closed environment and is not
  interoperable with other OnionCats in the wild because by default the names and
  IPs are verified to be correct.
  This option may be specified multple times.
  Alternatively you could put the IP/hostname pairs into the OnionCat hosts file
  (see option -g).
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
* **-D**  
  Disable OnionCat's DNS lookup. If OnionCat has to make an outgoing connection
  but no suitable entry is found in the internal hosts db, OnionCat will do a DNS
  query at the hosts found in the internal hosts db. This option deactivates this
  feature.  
  Hostname lookups are enabled by default since OnionCat4.
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
  
* **-E** _s_  
  This option sets the expiry time in secondes for remote entries in the internal
  hosts db.  
  If the TTL of an entry expires, OnionCat will try to renew the entry by
  connecting to the remote OnionCat to retrieve a new keepalive. If it is
  unreachable it will retry after some time again. If it was unreachable for more
  than _s_ seconds, the entry will be removed from the internal hosts db.  
  The default expiry time is 604800 seconds which is 7 days.
  
* **-f** _config file_  
  Read initial configuration from _config file_. 
* **-g** _hosts\_path_  
  Set the path to the hosts file. This option automatically enables option -H
  (see there). If -g is not set, the path defaults to
  SYSCONFDIR/tor/onioncat.hosts where SYSCONFDIR typically is /etc or
  /usr/local/etc.  
  On exit, OnionCat saves all collected hosts entries to
  DATADIR/onioncat/hosts.cached. This file is pulled in automatically at the next
  startup again. The entries are also save regularly every 5 minutes. This is
  only done if the internal hosts db was modified, i.e. if new entries where
  collected during the period of the last save to prevent unnecessary storage
  interaction. Please note that if you manually delete the file on the command
  line, it will not be recreated if no new entries where collected afterwards.
* **-H**  
  This option disables the hosts reverse lookup in the internal hosts db. Host
  lookups are required for Tor's hidden services V3 as well as for I2P. Thus,
  disabling the lookup function by using this options does only make sense when
  using Tor's hidden services V2.  
  Reverse lookups are enabled by default since OnionCat4.
* **-h**  
  Display short usage message and shows options.
* **-i**  
  Convert _onion\_id_ to IPv6 address and exit.
* **-I**  
  Run OnionCat in GarliCat (I2P) mode.
* **-J**  
  Disable remote hostname validation. OnionCat is able to receive remote
  hostnames from keepalive messages and DNS queries. OnionCat validates if these
  names "make sense", i.e. it checks if the name is a valid onion name, and it
  checks if the name translates to the right IP.  
  Hostname validation is enabled by default.  
  This is a security feature. Rogue OnionCats could send special crafted
  keepalives or DNS answers which may trick OnionCat into connecting somewhere
  else instead outside of the Tor network or to a fake hidden service.
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
  Use TAP device instead of TUN device. There are a few differences. See TAP
  DEVICE later.
* **-P** _[pid file]_  
  Create _pid file_ at _pid\_file_. If the option parameter is omitted
  OnionCat will create a pid file at **/var/run/ocat.pid**. In the latter case
  it must not be the last option in the list of options or the options list is
  terminated with a "--".
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
  Please note that this option does only work if the remote OnionCat does NOT run
  in unidirectional mode which is default since SVN version 555 (see option
  **-U**).
  So usually you will not use this option.
* **-S**  
  OnionCat runs a lightweight DNS services to respond to DNS queries from other
  OnionCats (see also option **-D**). This option disables this DNS service.
  It responds only to reverse lookups within the Tor (FD87:D87E:EB43::/48) or I2P
  (FD60:DB4D:DDB5::/48) prefix.  
  The name service is enable by default.
* **-s** _port_  
  Set OnionCat's virtual hidden service port to _port_. This should usually
  not be changed.
* **-t** _(IP|[IP:]port)_  
  Set Tor SOCKS _IP_ and/or _port_. If no _IP_ is specified 127.0.0.1
  will be used, if no _port_ is specified, 9050 will be used as default. If
  compiled on Windows with Cygwin 9150 will be used because this is the default
  for the Tor browser bundle. In GarliCat mode it defaults to 9051.
  IPv6 addresses must be escaped by square brackets.  
  The special parameter _"none"_ disables OnionCat from making outbound
  connections. This shall be used only in special test scenarios.
* **-T** _tun\_dev_  
  TUN device file to open for creation of TUN interface. It defaults to
  /dev/net/tun on Linux and /dev/tun0 on most other OSes, or /dev/tap0 if TAP
  mode is in use. Setup of a TUN device needs root permissions. OnionCat
  automatically changes its uid and gid after the TUN device is set up correctly.
* **-U**  
  Deactivate unidirectional mode. Before SVN version 555 OnionCat ran only in
  bidirectional mode. This is that a connection to another OC was used for
  outgoing _and_ incoming packets. Since this could be a security risk under
  certain conditions, unidirectional mode was implemented in SVN r555 and set to
  default. With this option bidirectional mode can be enabled again. Please note
  that the unidirectional mode does not interoperate with option **-R** if the
  remote OC is working in unidirectional mode.
  If option **-R** is not used (which is the regular case), unidirectional und
  bidirectional OnionCats can be mixed.
  Please note that the only advantage of bidirectional mode is that it has a
  lower setup time since it needs only one Tor circuit. Unidirectional mode needs
  two circuits, one for each direction.
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

For a detailed explaination about the interaction between OnionCat4 and HSv3
have a look at the document doc/INTRO_TO_ONIONCAT4.txt found in the source
folder or on GIthub at
https://github.com/rahra/onioncat/blob/master/doc/INTRO_TO_ONIONCAT4.txt .

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
The default settings changed since OnionCat4 (versions &gt;= 0.4.0). Actually
hosts-lookup is now on by default and the meaning of option **-H** was
inverted. This is because OnionCat4 is specifically configured to better match
the necessities for Tor's hidden services V3.


<a name="files"></a>

# Files

$HOME/.ocat/connect_log


<a name="author"></a>

# Author

Concepts, software, and man page written by Bernhard R. Fischer
&lt;[bf@abenteuerland.at](mailto:bf@abenteuerland.at)&gt;.


<a name="credits"></a>

# Credits

Credits go to Ferdinand Haselbacher, Daniel Haslinger, Wim Gaethofs,
Marshalbanana, all package maintainers of several Linux and BSD distros, and
many others who have contributed and reported bugs.


<a name="see-also"></a>

# See Also

Onioncat source code https://github.com/rahra/onioncat

Further docs and howtos are found at https://github.com/rahra/onioncat/tree/master/doc

OnionCat source packages are also found at https://www.abenteuerland.at/ocat/download/Source/

Tor project homepage https://www.torproject.org/

I2P project homepage https://geti2p.net/


<a name="copyright"></a>

# Copyright

Copyright 2008-2023 Bernhard R. Fischer.

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

