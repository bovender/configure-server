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


Setting up a Ubuntu Server VM
-----------------------------

To 'play' with a Ubuntu Server, you can quickly set up a
[VirtualBox](http://www.virtualbox.org) machine.

- Network configuration: I recommend 'host only' network to keep
  the server in a sandbox. Selecting 'host only' will create an
  additional network interface (e.g., <tt>vboxnet0</tt>) on the
  host. _Before starting the virtual machine_, make sure to	disable
  the DHCP server (<tt>File</tt> &rarr; <tt>Preferences</tt>
  &rarr; <tt>Network</tt> &rarr; <tt>Edit (space)</tt>).
- To tell the host about the server, sudo-edit <tt>/etc/hosts</tt>
  _on the host system_. For example, if you gave your server the
  fully qualified domain name "test.local", insert a line
  <tt>192.168.56.__101__ test.local</tt>.
- After starting up the virtual machine and installing the Ubuntu
  Server (from a previously [downloaded ISO
  file](http://www.ubuntu.com/download/server)), sudo-edit the
  file <tt>/etc/network/interfaces</tt>:
  ```
  auto eth0
  iface eth0 inet static
	address 192.168.56.__101__
	netmask 255.255.255.0
  ```
- Note that this configuration does not give the virtual server
  access to the internet! If you want to do this, configure an
  additional network interface for the virtual machine as 'NAT'
  (from the VirtualBox GUI). Then, add <tt>auto eth1</tt> and
  <tt>iface eth1 inet dhcp</tt> to the interfaces file.


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

<!-- vim:set tw=70 fo=tcroqn flp=\\(^|\\s{-}\\)[-*]\\s* : -->
