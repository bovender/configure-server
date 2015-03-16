___Note: This script is unfinished, but it does accomplish setting up
a mail server and IMAP server and Horde. I will continue to work on it
when I have time.___

Configure-server shell script
=============================

The configure-server script automagically configures a remote [Ubuntu
Linux](http://www.ubuntu.com/business/server/overview) or Debian
Server.

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

The script is being developed on Ubuntu 14.04 'Trusty Tahr' Server
Edition. It should run on a current Debian server as well.

During installation of the operating system, you should request a LAMP
setup and of course an SSH daemon.


Features
--------

The script configures the following services:

- Certificate-based SSH login
- [Postfix][] mail server with user management in LDAP directory and
  SMTP-AUTH and TLS/STARTTLS support
- [Dovecot][] IMAP/POP3 server with user management in LDAP directory
  and TLS/STARTTLS support
- [OpenLDAP][] server for central user management and single sign-on
- [Horde][] groupware
- It also creates an Apache2 virtual host and an MySQL user and
  database for an [OwnCloud][] cloud server; you only need to download
  and install the current OwnCloud release.


Customizing the script
----------------------

The script __must__ be customized by means of a couple of
configuration variables right at the top. Most importantly, if you
want to use the script on your own server, you __must__ change at
least the following variables:

- `$domain`
- `$tld`
- `$user` -- this should be the same user that you created during
  installation of Ubuntu Server edition.
- `$full\_user\_name`

You will find all customization variables at the top of the script.


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

The configuration notes assume that you have a basic knowledge of the
software. If you are (like me) a server newbie, you may find the
following resources (online & offline) useful:

- Postfix:  <www.postfix.org>, [The Book of Postfix][pf-book]
- Dovecot:  <www.dovecot.org>
- OpenLDAP: [Zytrax' Guide for Rocket Scientists][zytrax]
- [Ubuntu Server Guide][guide]


### LDAP ###

I chose to set up an LDAP directory server because I was intrigued by
the notion of a unified sign-in (single sign-in) for all services, as
well as a private and shared address books that are accessible from
remote clients such as Thunderbird.

LDAP layout is heavily inspired by [The Book of Postfix][pf-book].

The root of the data information tree (DIT) is construed from the
`$domain` and `$tld` variables defined in the script.

> If the OpenLDAP server does not accept your password, issue `sudo
dpkg-reconfigure slapd` and enter `$domain.$tld` when asked about the
machine name.

User information is stored unter `ou=users,dc=$domain,dc=$tld` The
entries' structural object class is `inetOrgPerson`. To be able to
store information about mail aliases, the Postfix documentation
[suggests][pf-ldap] using attributes such as `mailDrop` and
`mailAcceptingGeneralId`. [The Book of Postfix][pf-book] (first German
edition) also uses `mailDrop` in an example setup of [Postfix][] and
[Courier-IMAP][]. The problem here is that these attributes are not
defined in the schemes that [OpenLDAP][] ships with on Ubuntu Server.
The _cosine_ schema does include a structual object class
`pilotPerson`, which defines attributes such as `otherMail` which one
could use as a storage field for aliases. But since both
`inetOrgPerson` and `pilotPerson` are _structural_ classes, you cannot
assign an entry to both of them at the same time. Therefore, I
downloaded the Courier schema from the Ubuntu repositories, converted
it to [OLC][zytrax-olc] ("cn=schema,cn=config") format, and included
it in the script.

Creating new attributes and classes without registered object ID (OID)
is not considered good LDAP practice. Therefore I refrained from
simply creating my own objectClass and chose to use the Courier
schemas.

To enable Postfix and Dovecot to look up information in the LDAP
directory, another branch of the DIT is created as
`ou=auth,dc=$domain,dc=$tld`; the corresponding entries are:

        cn=dovecot,ou=auth,dc=$domain,dc=$tld
        cn=postfix,ou=auth,dc=$domain,dc=$tld

These two users have ACL-controlled access to
`ou=users,dc=$domain,dc=$tld`.

In summary, the DIT that the script sets up looks as follows:

_TODO_

__Important note:__ OpenLDAP is _extremely_ picky about spaces in LDIF
files. Ordinarily every line is expected to have no leading spaces. If
a line is continued, it must have a _trailing_ space, and the
continuation line must have one _leading_ space. In my experience, a
common cause of LDAP import errors is omission of the _trailing_ space
on a continued line!


### Postfix ###

The entire Postfix setup is _heavily_ inspired by [The Book of
Postfix][pfbook].

Even though my server is intended for a rather small group of people,
I resorted to configuring Postfix for virtual users, rather than users
registered on the Linux system, to make it more secure and easier to
maintain. In my setup, all virtual users share the same domain.
Therefore, in the spirit of keeping things [DRY][], the domain part of
all e-mail addresses is omitted from the LDAP entries. As a
consequence, the various configuration directives (LDAP queries,
Dovecot's mailbox directive) contain placeholders for the 'local' part
of an e-mail address, rather than the fully-qualified address.

Once an email is accepted, we let Postfix hand it over to the Dovecot
LDA by virtue of a piped transport. In this context it is important to
understand how Postfix [rewrites addresses][pf-addr]. As soon as
we replace Postfix' own `local` transport with Dovecot, the
`local_aliases` map no longer works. This is because the
`local_aliases` map is used during address rewriting *when an e-mail
is delivered*, rather than *when an e-mail is received*. With Dovecot
set up as local delivery agent, Postfix will *never* consult
`local_aliases`. 


[postfix]:    http://www.postfix.org
[pf-book]:    http://www.postfix-book.com
[pf-addr]:    http://www.postfix.org/ADDRESS_REWRITING_README.html
[pf-ldap]:    http://www.postfix.org/LDAP_README.html#example_virtual
[dovecot]:    http://www.dovecot.org
[courier]:    http://www.courier-mta.org/imap
[horde]:      http://www.horde.org
[openldap]:   http://www.openldap.org
[owncloud]:   http://www.owncloud.org
[zytrax]:     http://zytrax.com/books/ldap
[zytrax-olc]: http://www.zytrax.com/books/ldap/ch6/slapd-config.html#use-schemas "OLC: OnLine Configuration, a feature of newer OpenLDAP versions"
[guide]:      https://help.ubuntu.com/12.04/serverguide/index.html
[dry]:        http://en.wikipedia.org/wiki/Don't_repeat_yourself


### Horde Webmail ###

Horde Webmail Edition is installed and configured with a subdomain.
The subdomain's default name is 'horde' and can be customized in the
`$horde_subdomain` variable.

Horde will ask you where to install; you may want to use `/var/horde`.
The installation script will ask you for the connection parameters for
the MySQL server, so you should have these at hand when running the
script.


MySQL users
-----------

Two MySQL users and databases are automatically created, one for the
Horde groupware and one for OwnCloud.

The 'horde' user is granted access to the 'horde' database; the
predefined subdomain is 'horde'.

The 'owncloud' is granted access to the 'owncloud' database; the
predefined subdomain is 'cloud' (not owncloud, I found that's too
long).

Thus, if you have `$domain=example` and `$tld=com`, the resulting web
addresses for your applications are `horde.example.com` and
`cloud.example.com`.

Whenever the `configure-server` script is run, it creates new random
passwords for the two MySQL users. The passwords are mailed to the
master user, and they are also stored in `~/mysql-passwords`. Make
sure to delete this file and the mail when you have memorized the
passwords ;-)


SSL certificates
----------------

If a USB stick named `CA` is detected on the local computer (not on
the server), the `configure-server` script will create a custom
Certificate Authority (CA) and a number of certificates that are
signed by this custom CA. The CA certificates will be stored on the
USB stick. The signed certificates are uploaded to the server. When
the script is run on the server, it will check for the presence of
certificates in the home directory, and move them to the appropriate
place.

The mail and IMAP servers and the Horde and OwnCloud virtual Apache2
hosts are configured to use these certificates.

_You must use this feature at least once, or else your server will
complain about missing certificates. All it takes is to plug in a USB
drive named 'CA'._


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

If you run the `configure-server` script in the VirtualBox terminal
(i.e., not in an SSH session), the script will detect that it is
running in a VirtualBox system and install the Guest Additions,
provided the installer has been 'inserted' into the virtual CD-ROM
drive.
   

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
