Configure-server shell script
=============================

The configure-server script automagically configures a [Ubuntu
Linux](http://www.ubuntu.com/business/server/overview) Server.

I am a server newbie, and while I am putting together all 
configuration steps needed for a (more or less) complete server setup, 
I decided to put everything into a Bash script that I can execute on 
the remote server.

__This script is under active development and not yet ready for 'real'
use.__

__DISCLAIMER: USE THIS SCRIPT AT YOUR OWN RISK! I ASSUME NO
RESPONSIBILITY OR LIABILITY FOR ANY LOSS OF DATA, COMPROMISE OF
PRIVACY, OR ANY OTHER MISHAP THAT MAY RESULT FROM USING THIS SCRIPT.__

I mainly use the script to configure a server running in a VirtualBox
VM. See below for how to quickly set up a Ubuntu Server virtual
machine.


Prerequisites
-------------

The script is being developed on Ubuntu 12.04 'Precise Pangolin' Server
Edition. It should hopefully run on a current Debian server as well,
though I have not tested this (yet).

The only prerogative for this script is that you have installed Ubuntu
Server with the following options:

- LAMP
- Postfix

The script does not support name server (DNS) configuration.


Features
--------

The script configures the following services:

- Certificate-based SSH login
- [Postfix](http://postfix.org) mail server with user management in LDAP directory and
  SMTP-AUTH and TLS/STARTTLS support
- [Dovecot](http://dovecot.org) IMAP/POP3 server with user management in LDAP directory
  and TLS/STARTTLS support
- [OpenLDAP](http://openldap.org) server for central user management and single sign-on
- [Horde](http://horde.org) groupware
- [OwnCloud](http://owncloud.org) cloud server


Customizing the script
----------------------

The script can (and should) be customized by means of a couple of 
configuration variables right at the top. Most importantly, if you 
want to use the script on your own server, you __must__ change at 
least the following variables:

- <tt>$domain</tt>
- <tt>$tld</tt>
- <tt>$user</tt>
- <tt>$full\_user\_name</tt>


Running the script
------------------

When you have customized the script, you can run it locally:

	./configure-server.sh

The script will detect that it is not being executed on a server and
will offer to upload itself to the server that you indicated (using
the <tt>$domain</tt> and <tt>$tld</tt> variables). It can then log you
into the secure shell on the server, where you can simple issue the
same command again. In a few moments, you should have a fully
functional server!

If you happen to modify the script on the server, but run it again
locally, the script will fetch the updated script from the server
before logging you in.


Configuration notes
-------------------

TODO


Setting up a Ubuntu Server VM
-----------------------------

To 'play' with a Ubuntu Server, you can quickly set up a
[VirtualBox](http://www.virtualbox.org) machine.

Since you want to communicate via SSH with the virtual server (to
simulate a remote real server), it is important to configure the
network. I have configured three network cards for my virtual server:

1. Host-only network (<tt>eth0</tt>). This is used for SSH connections
   from my laptop to the server. It is configured to use static IPs
   (see below).
2. Adapter 2 is bridged to my host's wireless card.
3. Adapter 3 is bridged to my host's ethernet card.

The reason for this apparent complexity is that my laptop is not
always connected to the internet, and if it is, it may use wireless or
ethernet. Using a host-only adapter allows me to have my own 'virtual'
network regardless of whether my laptop is online or not.
   

### Configuring static IP for the host and the guest ###
   
Since I do not configure a nameserver, I must make sure that the
laptop and virtual server can always communicate. This is accomplished
using static IP.

Disable the VirtualBox DHCP server for the host-only network
(<tt>File</tt> &rarr; <tt>Preferences</tt> &rarr; <tt>Network</tt>
&rarr; <tt>Edit (space)</tt>).

To tell the host about the server, sudo-edit <tt>/etc/hosts</tt> _on
the host system_. For example, if you gave your server the fully
qualified domain name "test.local", insert a line
<tt>192.168.56.__101__ test.local</tt>.

After starting up the virtual machine and installing the Ubuntu Server
(from a previously [downloaded ISO
file](http://www.ubuntu.com/download/server)), sudo-edit the file
<tt>/etc/network/interfaces</tt>:

	auto eth0
	iface eth0 inet static
	address 192.168.56.101
	netmask 255.255.255.0

The other two interfaces (<tt>eth1</tt> and <tt>eth2</tt>) on the
server are configured to *not* automatically connect (i.e., there is
no <tt>auto ethX</tt> line in <tt>/etc/network/interfaces</tt> on the
server). This prevents the server from spending a long time waiting
for network information on startup when my laptop is not connected to
the internet.

Since the configure-server script needs to download a number of
packages from the repositories, you need to make sure to have an
internet connection:

	sudo ifup eth1


License
-------

The script is made available und the [MIT
license](http://opensource.org/licenses/mit-license.php).

Copyright (c) 2012 Daniel Kraus (bovender)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


<!-- vim:set tw=70 fo=tcroqn : -->
