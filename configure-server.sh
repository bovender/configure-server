#!/bin/bash

# #######################################################################
# Configure-server.sh
# Script to configure a Ubuntu server.
# (c) Daniel Kraus (bovender) 2012
# MIT license.
#
# !!! USE AT YOUR OWN RISK !!!
# The author assumes no responsibility nor liability for loss of data,
# disclose of private information including passwords, or any other 
# harm that may be the result of running this script.
# #######################################################################

# Configuration variables
subdomain=bdkraus
domain=fritz
tld=box
server_fqdn=$subdomain.$domain.$tld
server_fqdn=${server_fqdn#.} # Remove the leading dot (if no subdomain)
user=daniel
full_user_name="Daniel Kraus"
# simple password for demonstration purposes (will be used in LDAP)
pw=pass 
vmailuser=vmail
vmailhome=/var/$vmailuser

# Postfix configuration directories
postfix_base=/etc/postfix
postfix_main=$postfix_base/main.cf
postfix_master=$postfix_base/master.cf
postfix_ldap_dir=$postfix_base/ldap

# Dovecot configuration directories
dovecot_base=/etc/dovecot
dovecot_confd=$dovecot_base/conf.d
dovecot_ldap_dir=$dovecot_base/ldap

# LDAP DNs
ldapbaseDN="dc=$domain,dc=$tld"
ldapusersDN="ou=users,$ldapbaseDN"
ldapauthDN="ou=auth,$ldapbaseDN"

# Internal ('work') variables
homepage="http://github.com/bovender/configure-server"
msgstr="*** "
bold=`tput bold`
normal=`tput sgr0`
restart_postfix=0

shopt -s nocasematch

# #######################################################################
# Helper functions
# #######################################################################

# Prompts the user for a y/n choice
# $1 - prompt
# $2 - variable to store the answer into
# $3 - default answer
# Returns 0 if non-default answer, 1 if default answer.
yesno() {
	if [[ -n $3 && ! $2 =~ [yn] ]]; then
		echo "### Fatal: yesno() received default answer '$2', which is neither yes nor no."
		exit 99
	fi
	local choice="yn"
	[[ $3 =~ y ]] && local choice="Yn"
	[[ $3 =~ n ]] && local choice="yN"
	echo -n $1" [$choice] "
	local answer=x
	until [[ -z $answer || $answer =~ [yn] ]]; do
		read -s -n 1 answer
	done
	eval $2="$answer"
	[[ -z $answer ]] && eval $2="$3"
	echo $answer
	[[ $answer =~ $3 ]] && return 1
	return 0
}

# Prints out a heading
heading() {
	echo -e $bold"\n$msgstr$1"$normal
}

# Prints out a message
# (Currently this uses the heading() function, but may be adjusted
# according to personal preference.)
message() {
	heading "$1"
}


# #######################################################################
# Begin script
# #######################################################################

if [[ $(whoami) == "root" ]]; then
	echo "Please do not run this script as root. The script will sudo commands as necessary."
	exit 1
fi

heading "This will configure the Ubuntu server. ***"


# ########################################################################
# Find out about the current environment
# ########################################################################

# Use virt-what to determine if we are running in a virtual machine.
if [ -z `which virt-what` ]; then
	heading "Installing virt-what..."
	sudo apt-get install -qy virt-what
fi

heading "Requesting sudo password to find out about virtual environment..."
vm=`sudo virt-what`
if [ "$vm" == 'virtualbox' ]; then
	heading "Running in a VirtualBox VM."
	if [ ! -d /opt/VBoxGuestAdditions* ]; then
		heading "Installing guest additions... (please have CD virtually inserted)"
		sudo mount /dev/sr0 /media/cdrom
		if [ $? -eq 0 ]; then
			sudo apt-get install dkms build-essential
			sudo /media/cdrom/VBoxLinuxAdditions.run
		else
			heading "Could not mount guest additions cd -- exiting..."
			exit 1
		fi
	else
		heading "VirtualBox guest additions are installed."
	fi
else # not running in a Virtual Box
	# if this is the server, the script should be executed in an SSH
	# if no SSH is found, assume that this is the remote desktop computer
	# (assuming 
	if [ -z "$SSH_CLIENT" ]; then
		heading "You appear to be on a remote desktop computer."
		echo "Configured remote: $bold$user@$server_fqdn$normal"
		yesno "Synchronize the script with the one on the server?" answer y
		if (( $? )); then
			message "Updating..."
			rsync -vuza $0 $user@$server_fqdn:.
			rsync -vuza $user@$server_fqdn:$(basename $0) .
			if (( $?==0 )); then
				yesno "Log into secure shell?" answer y
				if (( $? )); then
					heading "Logging into server's secure shell..."
					exec ssh $user@$server_fqdn
				else
					message "Bye."
				fi
			else
				echo "Failed to copy the file. Please check that the server is running "
				echo "and the credentials are correct."
			fi
		else
			echo "Bye."
		fi
		exit
	else
		heading "Running in a secure shell on the server."
	fi
fi

# From here on, we can be pretty sure to be on the server.
# Let's check for pwgen (needed to generate passwords)
if [[ -z $(which pwgen) ]]; then
	heading "Installing pwgen..."
	sudo apt-get -qy install pwgen
fi

# Internal passwords for LDAP access
postfix_ldap_pw=$(pwgen -cns 32 1)
dovecot_ldap_pw=$(pwgen -cns 32 1)


# #####################################################################
# Now let's configure the server. 
# Everything below this comment should only be executed on a running
# server. (The above parts of the script should make sure this is the
# case.)
# #####################################################################

# Prevent Grub from waiting indefinitely for user input on a headless server.

if [[ -n $(grep "set timeout=-1" /etc/grub.d/00_header) ]]; then
	yesno "Patch Grub to not wait for user input when booting the system?" answer y
	if (( $? )); then
		heading "Patching Grub..."
		patch /etc/grub.d/00_header <<-'EOF'
			--- 00_header	2012-04-17 20:20:48.000000000 +0200
			+++ 00_header-no-timeout	2012-07-10 22:53:26.440676690 +0200
			@@ -233,7 +233,7 @@
			 {
				 cat << EOF
			 if [ "\${recordfail}" = 1 ]; then
			-  set timeout=-1
			+  set timeout=${2}
			 else
			   set timeout=${2}
			 fi
		EOF
		sudo update-grub
	fi
else
	heading "Grub is already patched."
fi


# Restrict sudo usage to the current user

if [[ ! $(sudo grep "^$(whoami)" /etc/sudoers) ]]; then
	yesno "Make $(whoami) the only sudoer?" answer y
	if (( $? )); then
		heading "Patching /etc/sudoers"
		# To be on the safe side, we patch a copy of /etc/sudoers and only
		# make the system use it if it passes the visudo test.
		sudo sed 's/^\(%admin\|root\|%sudo\)/#&/'  /etc/sudoers > configure-sudoers.tmp
		echo 'daniel	ALL=(ALL:ALL) ALL ' | sudo tee -a configure-sudoers.tmp > /dev/null

		# Visudo returns 0 if everything is correct; 1 if errors are found
		sudo visudo -c -f configure-sudoers.tmp
		[[ $? ]] && sudo cp configure-sudoers.tmp /etc/sudoers && rm configure-sudoers.tmp
	fi
else
	heading "Sudoers already configured."
fi


# ##################
# LDAP configuration
# ##################

if [[ $(dpkg -s slapd 2>&1 | grep "not installed") ]]; then
	heading "Installing LDAP..."
	sudo apt-get -qy install slapd lapd-utils
else
	heading "LDAP already installed."
fi

# DIT:
# http://www.asciiflow.com/#6112247197461489368/1725253880
#                                     +----------------+
#                                     |dc=domain,dc=tld|
#                                     +----------------+
#                        +-----------+                   +-----------+
#                        |  ou=auth  |                   |  ou=users |
#                        +-----------+                   +-----------+

if [[ -z $(sudo ldapsearch -LLL -Y external -H ldapi:/// -b "cn=config" "cn=schema" dn) ]]
then
	# Add the schema, ACLs and first user account to LDAP.
	# Be aware that LDAP is picky about leading space!

	message "Adding schema and access control lists (ACLs) to LDAP's cn=config..."
	# Ubuntu pre-configures the OpenLDAP online configuration such
	# that it is accessible as the system root, therefore we sudo
	# the following command.
	sudo ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
# Configure ACLs for the hdb backend database:
# First, remove the existing ACLs:
dn: olcDatabase={1}hdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {0}

# Then, add our own ACLs:
dn: olcDatabase={1}hdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword by dn="cn=admin,$ldapbaseDN" write by dn="cn=dovecot,$ldapauthDN" read by anonymous auth by self write by * none

# Add courier-authlib-ldap schema:
# Converted from authldap.schema to cn=config format by D. Kraus, 29-Jul-12
# Original file extracted from:
# http://de.archive.ubuntu.com/ubuntu/pool/universe/c/courier-authlib/courier-authlib-ldap_0.63.0-4build1_amd64.deb
# Line breaks were removed on purpose, as strange errors occurred on import.
# Depends on: nis.schema, which depends on cosine.schema

dn: cn=authldap,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: authldap
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.1 NAME 'mailbox' DESC 'The absolute path to the mailbox for a mail account in a non-default location' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.2 NAME 'quota' DESC 'A string that represents the quota on a mailbox' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.3 NAME 'clearPassword' DESC 'A separate text that stores the mail account password in clear text' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.4 NAME 'maildrop' DESC 'RFC822 Mailbox - mail alias' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.5 NAME 'mailsource' DESC 'Message source' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.6 NAME 'virtualdomain' DESC 'A mail domain that is mapped to a single mail account' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.7 NAME 'virtualdomainuser' DESC 'Mailbox that receives mail for a mail domain' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.8 NAME 'defaultdelivery' DESC 'Default mail delivery instructions' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.9 NAME 'disableimap' DESC 'Set this attribute to 1 to disable IMAP access' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.10 NAME 'disablepop3' DESC 'Set this attribute to 1 to disable POP3 access' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.11 NAME 'disablewebmail' DESC 'Set this attribute to 1 to disable IMAP access' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.12 NAME 'sharedgroup' DESC 'Virtual shared group' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.13 NAME 'disableshared' DESC 'Set this attribute to 1 to disable shared mailbox usage' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.10018.1.1.14 NAME 'mailhost' DESC 'Host to which incoming POP/IMAP connections should be proxied' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )
olcObjectClasses: ( 1.3.6.1.4.1.10018.1.2.1 NAME 'CourierMailAccount' DESC 'Mail account object as used by the Courier mail server' SUP top AUXILIARY MUST ( mail $ homeDirectory ) MAY ( uidNumber $ gidNumber $ mailbox $ uid $ cn $ gecos $ description $ loginShell $ quota $ userPassword $ clearPassword $ defaultdelivery $ disableimap $ disablepop3 $ disablewebmail $ sharedgroup $ disableshared $ mailhost ) )
olcObjectClasses: ( 1.3.6.1.4.1.10018.1.2.2 NAME 'CourierMailAlias' DESC 'Mail aliasing/forwarding entry' SUP top AUXILIARY MUST ( mail $ maildrop ) MAY ( mailsource $ description ) )
olcObjectClasses: ( 1.3.6.1.4.1.10018.1.2.3 NAME 'CourierDomainAlias' DESC 'Domain mail aliasing/forwarding entry' SUP top AUXILIARY MUST ( virtualdomain $ virtualdomainuser ) MAY ( mailsource $ description ) )
EOF
fi

heading "Binding to LDAP directory..."
echo "For binding to the LDAP directory, please enter the password that you used"
echo "during installation of this server."
code=-1
until (( $code==0 )); do
	read -sp "LDAP password for cn=admin,$ldapbaseDN: " ldap_admin_pw
	if [[ $ldap_admin_pw ]]; then
		ldapsearch -LLL -w "$ldap_admin_pw" -D "cn=admin,$ldapbaseDN" \
			-b "$ldapbaseDN" "$ldapbaseDN" dc /dev/null
		code=$?
		if (( $code==49 )); then
			echo "Incorrect password. Please enter password again. Empty password will abort."
		fi
	else
		message "Empty password -- aborting. Bye."
		exit 1
	fi
done
if (( $code!=0 )); then
	message "LDAP server returned error code $code -- aborting. Bye."
	exit 2
fi

if [[ -z $(ldapsearch -LLL -w "$ldap_admin_pw" -D "cn=admin,$ldapbaseDN" -b "$ldapusersDN" "uid=$user" uid) ]]
then
	message "Adding an entry for user $user to the LDAP tree..."
	ldapadd -c -x -w $ldap_admin_pw -D "cn=admin,$ldapbaseDN" <<-EOF
		dn: $ldapusersDN
		ou: ${ldapusersDN%%,*}
		objectClass: organizationalUnit

		dn: uid=$user,$ldapusersDN
		objectClass: inetOrgPerson
		objectClass: CourierMailAlias
		objectClass: CourierMailAccount
		uid: $user
		sn: $(echo $full_user_name | sed 's/^.* //')
		cn: $full_user_name
		userPassword: $pw
		mail: $user
		maildrop: root
		maildrop: postmaster
		# The homeDirectory attribute is required by the schema, but we leave
		# it empty since we are going to use $vmailhome as the uniform base
		# for all accounts.
		homeDirectory: 
		EOF
else
	message "User $user already has an LDAP entry under $ldapusersDN."
fi


# ######################################################################
# Postfix configuration
# ----------------------------------------------------------------------
# NB: This assumes that postfix was included in the system installation.
# ######################################################################


# Enable system to send administrative emails

if [[ $(dpkg -s bsd-mailx 2>&1 | grep "not installed") ]]; then
	heading "Installing bsd-mailx package..."
	sudo apt-get -qy install bsd-mailx
else
	heading "bsd-mailx package already installed."
fi


# Install spamassassin, clamav, and amavisd-new

if [[ $(dpkg -s spamassassin 2>&1 | grep "not installed") ]]; then
	heading "Installing spamassassin..."
	sudo apt-get -qy install spamassassin
else
	heading "spamassassin already installed."
fi

if [[ -z $(grep -i 'ENABLED=1' /etc/default/spamassassin) ]]; then
	heading "Enabling spamassassin (including cron job for nightly updates)..."
	sudo sed -i 's/^ENABLED=.$/ENABLED=1/' /etc/default/spamassassin
	sudo sed -i 's/^CRON=.$/CRON=1/' /etc/default/spamassassin
	echo "Starting spamassassin..."
	sudo service spamassassin start
fi

if [[ $(dpkg -s clamav 2>&1 | grep "not installed") ]]; then
	heading "Installing clamav..."
	sudo apt-get -qy install clamav
else
	heading "clamav already installed."
fi

if [[ $(dpkg -s amavisd-new 2>&1 | grep "not installed") ]]; then
	heading "Installing amavisd-new..."
	sudo apt-get -qy install amavisd-new
else
	heading "amavisd-new already installed."
fi


# Configure Postfix to use LDAP maps
# TODO: remove 'true' from the following IF statement
# TODO: configure SASL and STARTTLS

if [[ true || ! -d $postfix_ldap_dir ]]; then
	heading "Configuring Postfix to use LDAP maps..."
	sudo mkdir $postfix_ldap_dir
	sudo chgrp postfix $postfix_ldap_dir
	sudo chmod 750 $postfix_ldap_dir
	sudo tee $postfix_ldap_dir/ldap-aliases.cf <<-EOF
		# Postfix LDAP map generated by $(basename $0)
		# See $homepage
		# $(date --rfc-3339=seconds)

		server_host = localhost

		bind = no
		bind_dn = cn=postfix,$ldapauthDN
		bind_pw = $postfix_ldap_pw

		search_base = $ldapusersDN
		scope = one

		# Use the %u parameter to search for the local part of an
		# email address only. %s would search for the entire string.
		query_filter = (&(objectClass=CourierMailAlias)(maildrop=%u))

		# The result_format uses %u to return the local part of an
		# address. To use virtual domains, replace %u with %s
		result_format = %u
		result_attribute = mail
		EOF
	sudo tee $postfix_ldap_dir/ldap-local-recipients.cf <<-EOF
		# Postfix LDAP map generated by $(basename $0)
		# See $homepage
		# $(date --rfc-3339=seconds)

		server_host = localhost

		bind = no
		bind_dn = cn=postfix,$ldapauthDN
		bind_pw = $postfix_ldap_pw

		search_base = $ldapusersDN
		scope = one

		# Use the %u parameter to search for the local part of an
		# email address only. %s would search for the entire string.
		query_filter = (&(objectClass=CourierMailAlias)(mail=%u))

		result_attribute = uid
		EOF
	sudo chgrp postfix $postfix_ldap_dir/*
	sudo chmod 750     $postfix_ldap_dir/*

	# Configure Postfix to use LDAP to resolve local aliases.
	# If you want to use virtual domains (which implicates resolving
	# full email addresses rather than the local part only), you need
	# to change this to virtual_alias_maps, and also use %s instead of
	# %u in the LDAP configuration file above.
	sudo postconf -e "alias_maps=proxy:ldap:$postfix_ldap_dir/ldap-aliases.cf"
	sudo postconf -e "local_recipient_maps=proxy:ldap:$postfix_ldap_dir/ldap-local-recipients.cf"
	restart_postfix=1
fi

# Create alias for current user
# TODO: remove this? when ldap is configured
if [[ -z $(grep "root:\s*`whoami`" /etc/aliases) ]]; then
	yesno "Create root -> $(whoami) alias?" answer y
	if (( $? )); then
		heading "Creating alias..."
		echo "root: $(whoami)" | sudo tee -a /etc/aliases
		sudo newaliases
	fi
else
	heading "Mail alias for root -> $(whoami) already configured."
fi

if [[ -z $(grep dovecot /etc/postfix/master.cf) ]]; then
	heading "Configuring Postfix to use Dovecot as MDA..."
	sudo tee -a /etc/postfix/master.cf <<EOF
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=$vmail:$vmail argv=/usr/lib/dovecot/deliver -f \${sender} -d \${recipient}
EOF
	if [[ -z $(grep dovecot /etc/postfix/main.cf) ]]; then
		sudo postconf -e "dovecot_destination_recipient_limit = 1"
		sudo postconf -e "local_transport = dovecot"
		sudo sed -i 's/^mailbox_command/#&/' /etc/postfix/main.cf
	fi
	restart_postfix=1
fi


# #######################################################################
# Dovecot configuration
# #######################################################################

if [[ ! -a $dovecot_confd/99-custom.conf ]]; then
	heading "Adding Dovecot custom configuration..."
	sudo tee $dovecot_confd/99-custom.conf > /dev/null <<EOF
# As Postfix will make sure that the destination user exists, we can
# tell Dovecot to allow_all_users.

auth-default {
	mechanisms: plain login digest-md5 cram-md5
}
passdb {
	driver: ldap
	args: $dovecot_ldap/dovecot-ldap.conf
}
userdb {
	driver: ldap
	args: $dovecot_ldap/dovecot-ldap.conf
}
EOF
	sudo chmod 644 $dovecot_confd/99-custom.conf
else
	heading "Dovecot custom configuration already present."
fi

# # TODO: make this use sasl
# if [[ ! -a $dovecot_ldap/dovecot-ldap.conf ]]; then
# 	sudo mkdir $dovecot_ldap
# 	sudo chown vmail:vmail $dovecot_ldap
# 	tee $dovecot_ldap/dovecot-ldap.conf <<-EOF
# 		uris = ldap://localhost
# 		dn = dovecot
# 		dnpass = dovecot_pass
# 		sasl_bind = no
# 		sasl_mech = DIGEST-MD5
# 		ldap_version = 3
# 		base = o=Abimus
# 		deref = never
# 		scope = subtree
# 		user_attrs = homeDirectory=home,uidNumber=uid,gidNumber=gid
# 		user_filter = (&(objectClass=posixAccount)(uid=%u))
# 		pass_attrs = uid=user,userPassword=password
# 		pass_filter = (&(objectClass=posixAccount)(uid=%u))
# 		default_pass_scheme = CLEARTEXT
# 		EOF
# fi

# Add the vmail user.
# No need to make individual user's directories as Dovecot will
# take care of this.
if [[ -z $(id $vmail) ]]; then
	heading "Adding vmail user..."
	sudo adduser --system --home $vmailhome --uid 5000 --group $vmail
	sudo chown $vmail:$vmail $vmailhome
else
	heading "User vmail already exists."
fi


# TODO:
# dovecot --> static userdb with allow_all_users
# (but make sure postfix verifies existence of user!)
# create proper maildir: /var/spool/vmail/{user}/Maildir with permissions

# Lastly, restart Postfix and Dovecot
if (( restart_postfix )); then sudo service postfix restart; fi
if (( restart_dovecot )); then sudo service dovecot restart; fi

# ######################
# PHPmyadmin
# ######################

if [[ $(dpkg -s phpmyadmin 2>&1 | grep "not installed" ) ]]; then
	heading "Installing phpMyAdmin..."
	sudo apt-get -qy install phpmyadmin
	if [[ ! $(grep ForceSSL /etc/phpmyadmin/config.inc.php) ]]; then
		echo "\$cfg['ForceSSL']=true;" | sudo tee -a /etc/phpmyadmin/config.inc.php
	fi
else
	heading "phpMyAdmin already installed."
fi



# ######################
# Horde configuration
# ######################

if [[ $(dpkg -s php-pear 2>&1 | grep "not installed" ) ]]; then
	heading "Installing PEAR..."
	sudo apt-get -qy install php-pear
else
	heading "PEAR already installed."
fi

if [[ ! -d /var/horde ]]; then
	heading "Installing Horde..."
	sudo pear channel-discover pear.horde.org
	sudo pear install horde/horde_role
	sudo pear run-scripts horde/horde_role
	sudo pear install horde/webmail
	webmail-install
else
	heading "Horde already installed."
fi

if [[ ! -a /etc/apache2/sites-enabled/horde ]]; then
	heading "Configuring horde subdomain for apache..."
	sudo tee /etc/apache2/sites-available/horde > /dev/null <<EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
	ServerAdmin webmaster@$server_fqdn
	ServerName horde.$server_fqdn
	DocumentRoot /var/horde
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory /var/horde>
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>

	ErrorLog ${APACHE_LOG_DIR}/error.log

	# Possible values include: debug, info, notice, warn, error, crit,
	# alert, emerg.
	LogLevel warn

	CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined

	SSLEngine on
	SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
	SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

	#SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
	<FilesMatch "\.(cgi|shtml|phtml|php)$">
		SSLOptions +StdEnvVars
	</FilesMatch>
	<Directory /usr/lib/cgi-bin>
		SSLOptions +StdEnvVars
	</Directory>

	BrowserMatch "MSIE [2-6]" \
		nokeepalive ssl-unclean-shutdown \
		downgrade-1.0 force-response-1.0
	# MSIE 7 and newer should be able to use keepalive
	BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown

</VirtualHost>
</IfModule>
EOF
	sudo a2ensite horde
	sudo service apache2 reload
else
	heading "Horde subdomain for apache already configured."
fi


# #######################################################################
# Finish up
# #######################################################################

mail -s "Message from configure-server.sh" root <<-EOF
	Hello,

	this is just to inform you that the configure-server script was run.

	Script: $0
	EOF

# vim: fo+=ro
