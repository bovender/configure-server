Configure-server Bash shell script
==================================

The configure-server script automagically configures a remote [Ubuntu
Linux](http://www.ubuntu.com/business/server/overview) or Debian
Server.

This script is intended to aid people like me: amateur server
administrators. It is entirely self contained, copies itself to a
remote server, and sets up a mail system as well as the following
other services:

- [Postfix][] mail server with user management in LDAP directory and
  SMTP-AUTH and TLS/STARTTLS support
- [Dovecot][] IMAP/POP3 server with user management in LDAP directory
  and TLS/STARTTLS support
- [OpenLDAP][] server with SSL/TLS for central user management and
  single sign-on
- [Horde][] groupware
- It also creates an Apache2 virtual host and an MySQL user and
  database for an [OwnCloud][] cloud server; you only need to download
  and install the current OwnCloud Server release.

__DISCLAIMER: USE THIS SCRIPT AT YOUR OWN RISK! I ASSUME NO
RESPONSIBILITY OR LIABILITY FOR ANY LOSS OF DATA, COMPROMISE OF
PRIVACY, OR ANY OTHER MISHAP THAT MAY RESULT FROM USING THIS SCRIPT.__

I mainly use the script to configure a server running in a VirtualBox
VM. See below for how to quickly set up a Ubuntu Server virtual
machine.


Supported operating systems
---------------------------

The script is being developed on Ubuntu 14.04 'Trusty Tahr' Server
Edition. It should run on a current Debian server as well.

During installation of the operating system, you should request a LAMP
setup and of course an SSH daemon.


SSL/TLS certificates
--------------------

Commercial SSL/TLS certificates are expensive. Because my server is
accessed from just a few computers that me and my family control, I
have chosen to act as my own Certificate Authority and not use
self-signed certificates. Thus, I just have to install  my own root
certificate on my own computer and on the computers of my family
members in order to benefit from hassle-free secured connections.

For those cases where the server is accessed from computers that do
not have the homegrown root certificate installed, the script
conveniently summarizes the certificate fingerprints, which can easily
be verified as needed (keeping a hardcopy of the fingerprints in the
wallet).


Usage
-----

Please read this before executing the script.

### Step 1: Installing the server

Install Ubuntu Server Edition on your server in the usual way. During
installation you should indicate that you want a LAMP stack, an SSH
server, and an internet mail system. (It's up to you to install other
services right away such as Samba, but the `configure-server` script
won't deal with those.)

The user account that is created by the Ubuntu installer is only
needed for low-level administrative work on the server (such as
running the `configure-server` script). Therefore, you
can (and should) use a complicated password (and maybe even
complicated user name). The `configure-server` script will set up an
LDAP directory for actual user management on the server, and this LDAP
directory will be populated with a main user (admin user) that serves
as administrator for e.g. Horde. The main user account stored in the
LDAP directory has nothing to do with the user account on the server.

### Step 2: Basic configuration of the script

Clone the repository (or simply download the script) to your __local__
computer. The script should not be executed as root (in fact, it will
refuse to run as root). It uses `sudo` internally as needed.

The first time you run the script, a configuration file
`configure-server.config` will be created. You __must__ edit this file
to tell the script the domain name of your server, as well as other
information. _Importantly, you need to edit the information for the
main server user._ Remember that this main user account will be stored
in the LDAP directory, and is different from the low-level user
account that you use to log into the secure shell on the server.

### Step 3: Generating SSL certificates

The second time you run the script, the configuration file will be
read. At this point, you should have an external USB drive labeled
`CA` plugged into your computer. The script will create a directory
`ca` on this USB drive (e.g., `/media/USERNAME/CA/ca`), which will
serve as a Certificate Authority for SSL certificates. The
certificates that the script creates will be signed with a root
certificate that is stored on the USB drive. _Make sure to keep this
USB drive in a safe place, as it contains the private key of your own
root certificate._ 

SSL certificates will be generated every time the script is run while
the `CA` USB drive is mounted. This way, you can conveniently update
your certificates, for instance if they are about to expire (default
lifetime is 5 years). All you need to do is plug in the USB drive, run
the script, and enter the passphrase for the CA private key.

### Step 4: Copying the script to the server

When the script is executed locally, it will offer to copy itself to
the remote server, and log into the SSH shell of the server.

One thing that the script does not currently do, but that you may want
to consider, is to `ssh-copy-id` your personal SSH key to the server
so you don't have to enter the password. You may also want to edit
`/etc/ssh/sshd_config` to disable password authentication (see
[docs][sshd-docs]).

### Step 5: Running the script on the server

Once you are logged into the secure shell on the server, run

    ./configure-server.sh

to start the actual server setup.

The script will now detect that it is being executed on the server,
and will start downloading required packages (via `apt-get` and `pear
install`), and it will adjust all sorts of configuration files. See
below for details.

At the end, you will see a summary printed on the screen, which is
also stored in `~/readme-configure-server` as well as mailed to the
root account (which is tied to the main user account in the LDAP
directory). 

The summary contains the user names and passwords of the control users
that were automatically created for Postfix, Dovecot, Horde, and
OwnCloud. These control users are required for LDAP and MySQL
authorization of these services. Normally you won't need the
information, but if you are going to install OwnCloud for example, you
will have to enter the control user's credentials during setup.

If you print out the SSL certificate fingerprints that are listed in
the summary, you can quickly verify your certificates if you ever
access the server from a computer that does not have your own root
certificate installed.


Configuration notes
-------------------

The configuration notes assume that you have a basic knowledge of the
services used. If you are (like me) a server newbie, you may find the
following resources (online & offline) useful:

- Postfix:  <www.postfix.org>, [The Book of Postfix][pf-book]
- Dovecot:  <www.dovecot.org>
- OpenLDAP: [Zytrax' Guide for Rocket Scientists][zytrax]
- [Ubuntu Server Guide][guide]


### User management with LDAP

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

    #                            +------------------+                   
    #                            | dc=DOMAIN,dc=TLD |                   
    #                            +--------+---------+                   
    #                                     |                             
    #                  +----------------------------------------+       
    #                  |                  |                     |       
    #            +-----+----+        +----+----+          +-----+-----+ 
    #  +---------+ ou=users |        | ou=auth |          | ou=shared | 
    #  |         +-+--------+        +----+----+          +-----+-----+ 
    #  |           |                      |                     |       
    #  |   +-------+--------+    +--------+---------+    +------+------+
    #  |   | uid=ADMIN_USER |    | cn=OWNCLOUD_USER |    | ou=contacts |
    #  |   +-------+--------+    +------------------+    +-------------+
    #  |           |             +------------------+                   
    #  |      +----+--------+    | cn=DOVECOT_USER  |                   
    #  |      | ou=contacts |    +------------------+                   
    #  |      +-------------+    +------------------+                   
    #  |                         | cn=HORDE_USER    |                   
    #  |   +----------------+    +------------------+                   
    #  +---+ uid=...        |    +------------------+                   
    #      +-------+--------+    | cn=POSTFIX_USER  |                   
    #              |             +------------------+                   
    #         +----+--------+                                           
    #         | ou=contacts |                                           
    #         +-------------+                                           
    #                                                                   
    #           USERS               CONTROL USERS          SHARED STUFF 
    #        with personal          for services           like shared  
    #        addressbooks                                  addressbook  
    #
    #
    #                            (created with http://www.asciiflow.com)
                                                                 

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


OwnCloud
--------

If you want to use OwnCloud Server, [download][oc] the latest release
to the server and extract the archive into `/var/`:

    sudo tar xjf owncloud-X.Y.Z.tar.bz2 -C /var/

> Adjust the ownerships and permissions of `/var/horde` and its
> subfolders as described in the OwnCloud administrator's manual!

Then, enable the Apache site that `configure-server` has already set
up for you:

    sudo a2ensite owncloud.config

Now, navigate to your OwnCloud site (e.g. `cloud.example.com`, see
configuration options above). Enter a user name and password for the
initial OwnCloud user.


Changelog
---------



Known issues
------------

- SSL certificate creation needs some love.
- Thunderbird does not read the LDAP address book. It connects to the
  LDAP server all right, but the address book incorrectly reports "0
  entries". I have yet to find out what the problem is.


Addendum: Securing phpMyAdmin
-----------------------------

`configure-server` apt-get-installs [phpMyAdmin][] for you and sets
the 'ForceSSL' to true (by adding a line to
`/etc/phpmyadmin/config.inc.php`). However, this still leaves your
phpMyAdmin login screen vulnerable for password hacking, since anybody
from anywhere can access it.

For heightened security, set the 'ForceSSL' config to `false` (you
won't need SSL any more with this approach), then add

    Order deny,allow
    Deny from all
    Allow from localhost

to `/etc/apache2/conf-available/phpmyadmin.conf` and reload the Apache
configuration.

Then, use an SSH tunnel to access phpMyAdmin from localhost:

    ssh -L 8080:localhost:80 $DOMAIN.$TLD

Use <http://localhost:8080/phpmyadmin> in your browser.
If you don't set 'ForceSSL' to `false` in the phpMyAdmin config, the
tunnel command would be

    ssh -L 8080:localhost:443 $DOMAIN.$TLD

But I don't see much sense in using SSL-secured transmission in an
SSH-secured tunnel. The browser would complain about an incorrect SSL
certificate because the host name 'localhost' does not match
'$DOMAIN.$TLD', so you will need  to compare the certificate's
fingerprint to be on the safe side. (I don't use SSL+SSH, I use just
the SSH tunnel.)


Addendum: Setting up a Ubuntu Server VM
---------------------------------------

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

[sshd-docs]:  https://help.ubuntu.com/community/SSH/OpenSSH/Configuring
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
[phpmyadmin]: http://www.phpmyadmin.net



<!-- vim:set tw=70 ts=4 sw=4 sts=4 et fo=tcroqn : -->
