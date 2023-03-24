# AN INTRODUCTION TO ONIONCAT4

Version 1.0, 2022/07/21, Bernhard R. Fischer <bf@abenteuerland.at>
Version 1.1, 2022/11/19, Bernhard R. Fischer <bf@abenteuerland.at>


## ABSTRACT

Since the beginning of the development of OnionCat in 2008 a lot has changed.
Most importantly this is the replacement of Tor's hidden services version 2 by
the new hidden services version 3. This had a severe impact on the
functionality of OnionCat.

This article gives on overview why the newer hidden services almost broke
OnionCat and explains the adaptions that have been made with OnionCat4 to work
as smooth as possible again even with the newer version 3 of hidden services.

OnionCat4 comes with a distributed hosts database based on the DNS protocol
which allows OnionCat nodes to dynamically exchange .onion hostnames between
each other.

OnionCat4 refers to the versions >= 0.4.x of OnionCat which is found on
[Github](https://github.com/rahra/onioncat). This article is written in respect
to version 0.4.6.


## 1 ABOUT ONIONCAT IN GENERAL

OnionCat is a VPN adapter which let's you connect an arbitrary number of hosts
together as if they were on the same network segment. This is what basically
every VPN adapter (such as e.g. OpenVPN) does. The differences between OnionCat
and any other VPN is that, firstly, OnionCat does not connect through the
Internet but through Tor's hidden services (or I2P's), and, secondly, it uses a
peer-to-peer approach. There is no central server or any other instance which
manages the network.

Because OnionCat connects through Tor, any traffic passing through OnionCat is
protected from surveillance.

Once a connection between two OnionCats is established, any network packets
(such as e.g. TCP, UDP, and ICMP) can pass through this tunnel as long as they
are IPv6-based. But since OnionCat assigns IPv6 addresses with the prefix
fd87:d87e:eb43::/48 to the tunnel interface, any point-to-point connection
between two nodes will work out-of-the box.


## 2 HIDDEN SERVICES AND THE GLUE BETWEEN ONIONCAT AND TOR

Tor offers hidden services which are a feature to connect to TCP-based services
(such as e.g. HTTP servers) within the Tor network, i.e. connections do never
exit to the Internet. Hidden services are addressed by special hostnames ending
with the top level domain .onion.

If Tor gets a request for such hostname it does not exit to the Internet but it
looks up the service within the Tor network itself and connects the TCP session
there.

OnionCat makes use of these hidden services. It has two interfaces. One is a
local tunnel interface which makes it able to receive IP packets from your
host. The other interface is TCP to the Tor proxy. If OnionCat receives an IP
packet on the tunnel interface, it reads the destination IP address of the
packet, translates it to a .onion hostname, requests a connection from Tor, and
sends the packet(s) there as soon as the connection is established. OnionCat
internally maintains a peer list which is the association of TCP sessions and
OnionCat IPv6 addresses.

The "magic" is the translation between IPv6 addresses and .onion hostnames. The
development of OnionCat started in 2008. At the time then .onion hostnames with
hidden services version 2 were encoded 80 bit long identifiers, such as e.g.
777myonionurl777.onion. Since IPv6 addresses have 128 bits, a translation back
and forth into a special chosen prefix was possible. For example
777myonionurl777.onion. would translate to
fd87:d87e:eb43:fffe:cc39:a873:6915:ffff and back again.

Since then several things changed and it was necessary to improve the
cryptography of Tor and make it more strong. This led to the development of
hidden services version 3 which come with 280 bit long identifiers. This
obviously does not fit into an IPv6 address any more.

These newer hidden services almost broke OnionCat and its smart address
translation technique and it became necessary to implement some kind of lookup
mechanism which let's OnionCat somehow retrieve the now much longer .onion URLs
associated to the OnionCat IPv6 addresses.


## 3 AN .ONION HOSTNAME LOOKUP MECHANISM

Actually OnionCat had a built-in lookup mechanism almost since the beginning
because I2P always used much longer identifiers. This original lookup mechanism
was just a flat hosts file with IPv6 address/hostname pairs in it.  Although
this basically works fine, it makes it necessary to manually maintain these
hosts files and urge people to exchange their hostnames in advance. The latter
is in some cases simply impossible and not feasible, e.g. if people use
BitTorrent on top of OnionCat.

OnionCat4 comes with a completely new lookup mechanism which should bring back
its old elegant way, at least partially. And with some community effort it may
become pretty powerful again.

Generally, doing a lookup means that there has to be some kind of database
which keeps those IP address/hostname records. In my opinion, it is totally
unrealistic to run some kind of centralized databases in the anonymous hidden
service world. Simply because who should/would reliably do this? Probably some
intelligence agency might jump in here ;)

OnionCat strictly follows a peer-to-peer approach. So it was necessary to
develop a distributed peer-to-peer lookup mechanism as well.


## 4 THE LOOKUP MECHANISM OF ONIONCAT4

The lookup mechanism of OnionCat4 is based on DNS. 3 main building blocks
where added to OnionCat:

1. An internal hosts database.
2. A lightweight DNS resolver.
3. A lightweight name server.

OnionCat4 internally maintains a hosts database. Each time a new connection has
to be opened, it looks up the hostname within this database. If the desired
hostname is not found it selects some of the hosts within this database and
sends DNS requests to them using its resolver. If at least one of these name
servers responds, the new hostname is added to the internal hosts database and
the next lookup will be successful.


### 4.1 THE HOSTS DATABASE

The hosts database basically is a list of entries. Each entry consists of an
IPv6 address (which is the key), the .onion hostname, a source identifier (see
below), an age (which is the timestamp when the entry was added), a TTL, and
some metric parameters. The latter are used and modified by the resolver.

The hosts database may be populated by 6 different sources as follows. The 1st
3 are local sources, the 2nd 3 are remote sources.

0. Its own hostname. There is always just a single entry.
1. Hostnames passed as command line arguments with option -A.
2. The hosts file. By default this is /usr/local/etc/tor/onioncat.hosts. It is
   pulled in at program startup and automatically re-read every time if the
   file was modified.
3. Keepalive packets. Every OnionCat sends at least one initial keepalive
   packet to the remote end. It contains its own hostname.
4. An authoritative answer of an OnionCat name server.
5. A non-authoritative answer of an OnionCat name server.

The order is important since it defines the priority of the source. The first
in the list has the highest priority. This means that an entry cannot be
overwritten by a source with a lower priority.

The complete internal hosts database is saved to disk at regular intervals and
at program exit (typically to `/usr/local/var/onioncat/hosts.cached`). The file
will be pulled in again at the next program startup. This is to not loose
remote entries across reboots. Entries of this file will never overwrite local
entries of the hosts file (`onioncat.hosts`) or command line entries (option -A).

The hosts database can be viewed during runtime on the controller interface, or
just have a look at the hosts.cached file. To get to the controller interface
just telnet to port 8066 on the localhost and issue the command `hosts`.


### 4.2 THE RESOLVER

The resolver is a simple lightweight resolver. Upon request it selects up to 5
hosts out of the hosts database and sends DNS requests to them. The name server
selection is based on the metric value of each entry in the hosts database.
Higher values are consider better. The metric algorithm may change in future
but at the time of writing this article it is calculated as follows (see
`ocathosts.c:hosts_metric()`):

```
metric = 1000 / source + acnt * 100 / qcnt

source: CLI = 1, hosts = 2, keepalive = 3, ...
acnt: answer count
qcnt: query count
```

Basically that means that hosts with a higher priority and a higher
answer/query ratio are considered better.

Technically the resolver does reverse lookups (PTR queries) because it tries
the find a hostname for a given IPv6 address. Queries are sent using UDP on
port 53.

Every time a query is sent the query counter (qcount) is increased. Successful
responses will increase the answer counter (acnt) of the hostname entry of the
name server. Responses will also update the TTL value of the hosts entry of the
corresponding name in the query.

The resolver may be invoked manually on the controller interface of OnionCat.
Telnet to port 8066 and use the built-in command `dig`.


### 4.3 THE NAME SERVER

The name server listens on UDP port 53 and replies to PTR queries. If a valid
query was received it looks up the desired address within the internal hosts
database. If an entry exists it sends back a proper response. If the source of
the entry was local, the authoritative answer flag (AA) is set in the response.

If no entry is found the name server replies with NXDOMAIN. The server does not
recursively resolve the request. To all other valid queries (e.g. A, MX, ...)
it will always respond with NXDOMAIN. Invalid queries may be answered with
FORMERR if possible (see RFC1034 and RFC1035 for more details on the DNS
protocol).

Since the name server implements the standard DNS protocol it may be queried
with any standard DNS tool, e.g. `dig` or `nslookup`.


### 4.4 DATABASE HOUSEKEEPING

A background thread maintains the internal hosts database. On regular intervals
the age and TTL values of the entries are checked. The default TTL is 2 hours
after which it initiates automatically outgoing connections directly to those
hosts to re-validate the entries. If a host is unreachable for more than 7
days, the entry is pruned.


## 5 DISCUSSION

With this new features built in, OnionCat has now the potential to be used as
it was before and maybe get an even bigger user base.

Every single OnionCat instance now maintains its own hosts database and can
connect and learn new entries by the hosts found in its database. Thereby the
list of valid hosts will dynamically grow. Because the database is regularly
saved to disk it will survive reboots even if they happened accidentally.

There are several scenarios possible. Let's discuss a few of them. Of course,
there is not just a single valid solution of implementation to the following
examples.


### 5.1 RUNNING ONIONCAT4 IN A GROUP OF KNOWN INSTANCES

A group of people use a set of OnionCat nodes to connect to each other. Assume
there are some notebooks (nodes N0 to N5) which are not permanently online and
some servers (nodes S0 to S5) which are online all the time. All instances have
Tor and OnionCat4 setup properly. Since hidden services version 3 require a
hostname lookup the OnionCats need additional configuration and will not just
magically work out of the box. At least one entry in the hosts database (except
its own address) is necessary.

Let's choose one of these servers (e.g. S0) which is said to be the most
reliable one. We let it collect all entries and define it as our master. Please
note that this is just a personal definition. It's a point of view. All
OnionCat instances are technically equal and have the same capabilities.

Step 1: Start OnionCat4 on all instances with the additional command line
argument "`-A <hostname_of_S0.onion>`".

Step 2: On the command line of each instance (except S0) ping the IPv6 address
of S0.

Step 3: Because each instance can properly resolve S0 (because the hostname is
already in every instance's hosts database because of -A), all of them will be
able to open a connection to S0. Since OnionCat sends an initial keepalive
packet, S0 will learn about all of those instances and its internal hosts
database (of S0) will immediately be populated with all the entries (N0-N5 and
S0-S5 in this example).

Now let's assume N0 wants to connect to N1 (e.g. let's ping the IPv6 address of
N1 on the command line of N0). N0 has no entry for N1 in its hosts database.
Thus it will try to resolve it and chooses a name server out of its hosts
database. This is S0 because at this moment it is the only entry in the
database. N0 will send a DNS query to S0 and will request the name for N1. S0
will receive the request and will reply with the hostname of N1. It had learned
the name of N1 already in step 3 of before.

N0 will receive the reply for the hostname of N1. It will add the name to its
own hosts database and can immediately open a connection to N1. After the
connection is established, N0 sends a keepalive to N1. As a result N1 now also
knows about N0 and can connect back (e.g. to send an echo reply).


### 5.2 RUNNING BITTORRENT ON TOP OF ONIONCAT4

In this scenario we have a large number of BitTorrent clients (seeders and
leechers) and at least one tracker. The tracker is the software which keeps
track on the IP addresses of the seeders and leechers. If a new leecher wants
to download a file, it 1st connects to the tracker which will in turn reply
with a list of IP address of where portions of the desired file may be
downloaded. The client then will directly connect to these hosts to download.

To make this work the tracker has to be run on a system wich runs OnionCat4 and
shall (only) be bound to the OnionCat IPv6 address. This can easily be done
with e.g. [opentracker](https://erdgeist.org/arts/software/opentracker/) which
is a robust and lightweight OpenSource BitTorrent tracker (compile it with
`-DWANT_V6`). The OnionCat on the tracker is run without any special parameters
(no -A needed).

Clients need 2 pieces of information. Both could be made public somewhere on
the Internet.

1. The .onion-hostname of the tracker.
2. A torrent file. It contains the information about the file to download and
   the URL of the tracker. In this case the URL is the OnionCat IPv6 address
   of the tracker, e.g. `http://[fd87:d87e:eb43:<ip_of_tracker>]:6969/announce`.

On the client run OnionCat4 with the option "`-A <hostname_of_tracker.onion>`".
Then fire up your favorite BitTorrent client and open the torrent file.

Since somebody was the first one to seed the file, his BitTorrent client (S0)
had to connect to the tracker. This happened through OnionCat4 and because of
that the tracker's OnionCat learned about the hostname of this initial seeder
(because of the keepalive).

If now a leecher (L0) opens the torrent file, the BitTorrent client will
connect to the tracker because of the URL within the torrent file. This will
happen through OnionCat. As a result the tracker's OnionCat will learn the IP
address of this leecher as well as the tracker itself. The tracker will then
reply with a list of IP addresses which is in this moment just the single
address of the 1st seeder (S0).

The BitTorrent client (L0) will now try to connect to S0. Since L0's OnionCat
does not yet have an entry for S0 in its database it will resolve it. It sends
a DNS query to the tracker's OnionCat because it is the only instance in the
hosts database. This OnionCat (the tracker) already knows about S0 and will
reply. As a result L0 can now connect directly to S0 and start leeching.

You can continue this game with additional clients resulting in a growing list
of hosts in the hosts database of the tracker's OnionCat. It will become a
major OnionCat name server. But also the clients themselves build up a larger
hostname list because they connect directly to the seeders. Thus, they can and
will also be used as name servers. Hence, the distributed knowledge of IPv6
address/hostname pairs grows in general.


## 6 CONCLUSION

It was exlained how OnionCat4 works and discussed in detail how the distributed
hosts database grows by the interaction between OnionCat nodes. Of course, this
is not a perfect solution as it did work with hidden services version 2. But
things change and hidden services version 3 have a stronger level of protection
in respect to cryptography, so OnionCat had to be adapted.

It cannot be predicted but it could happen that a critical mass of OnionCat
nodes may be reached in such a way that enough nodes are out there that every
new OnionCat can boot strap with just a single name server entry in its hosts
file. Maybe some nodes out there advance to "public" OnionCat name servers in
the hidden OnionCat world.

If this happens it is most likely that the metric algorithm has to be adapted.

Keep in mind that OnionCat is OpenSource. So everybody is invited to use it,
make suggestions, improve the code, add features, or have decent discussions
for a further development.


