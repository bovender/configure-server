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
mail=dk
full_user_name="Daniel Kraus"
# simple password for demonstration purposes (will be used in LDAP)
pw=pass 
vmailuser=vmail
vmailhome=/var/$vmailuser

# SSL certificate handling $ca_dir is the path to your own certificate
# authority. By default this is /media/CA/ca, meaning that your CA key is on a
# drive labeled "CA" (e.g., a USB stick). If your certificates are signed by a
# commercial CA, you may leave this empty. The script will auto-detect if the
# USB drive is mounted and offer to generate fresh certificates for the
# services that it will configure (Mail, LDAP, Apache virtual hosts, OwnCloud).
ca_dir=/media/daniel/CA/ca
ca_name=ca
cert_days=1825
cert_country=DE
cert_city=Wuerzburg
cert_state=Bavaria
cert_org=bovender
cert_ou="Certificate authority"
cert_company=bovender

# Postfix configuration directories
postfix_base=/etc/postfix
postfix_main=$postfix_base/main.cf
postfix_master=$postfix_base/master.cf

# Dovecot configuration directories
dovecot_base=/etc/dovecot
dovecot_confd=$dovecot_base/conf.d

# LDAP DNs
ldapbaseDN="dc=$domain,dc=$tld"
ldapusersDN="ou=users,$ldapbaseDN"
ldapauthDN="ou=auth,$ldapbaseDN"
adminDN="cn=admin,$ldapbaseDN"
# Do not change the following two, as 'dovecot' and 'postfix' are
# hard-coded elsewhere (namely, in the 'cn: ...' directives of LDIF)
dovecotDN="cn=dovecot,$ldapauthDN"
postfixDN="cn=postfix,$ldapauthDN"
hordeDN="cn=horde,$ldapauthDN"
pwhash="{SSHA}"

# MySQL
mysqladmin=root

# Horde parameters
horde_dir=/var/horde
horde_subdomain=horde
horde_database=horde

# Internal ('work') variables
homepage="https://github.com/bovender/configure-server"
msgstr="*** "
bold=`tput bold`
normal=`tput sgr0`
restart_postfix=0
ip=$(ip address show dev eth0 | awk '/inet / { print $2 }' | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}')

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

# Creates a backup file containing the original distribution's
# configuration
backup() {
	for f in "$@"; do
		if [[ ! -a "$f.dist" ]]; then
			sudo cp "$f" "$f.dist"
		fi
	done
}

# Prints out a heading
heading() {
	echo -e $bold"\n$msgstr$*"$normal
}

# Prints out a message
# (Currently this uses the heading() function, but may be adjusted
# according to personal preference.)
message() {
	heading "$*"
}

# Checks if a package is installed and installs it if necessary.
# This could also be accomplished by simply attempting to install it 
# using 'apt-get install', but this may take some time as apt-get
# builds the database first.
install() {
	local need_to_install=0
	# Use "$@" in the FOR loop to get expansion like "$1" "$2" etc.
	for p in "$@"; do
		if [[ $(dpkg -s $p 2>&1 | grep -i "not installed") ]]; then
			local need_to_install=1
			break
		fi
	done
	# Use "$*" in the messages to get expansion like "$1 $2 $3" etc.
	if (( $need_to_install )); then
		heading "Installing '$*'..."
		sudo apt-get install -qqy $@
	else
		heading "'$*': installed already."
	fi
}

# Synchronizes the script on the desktop with the one on the server
sync_script() {
	rsync -vuza $0 $user@$server_fqdn:.
	code=$?
	if (( code==0 )); then
		rsync -vuza $user@$server_fqdn:$(basename $0) .
		code=$?
	fi
	return $code
}

# Generates an SSL certificate
# Parameters:
# $1 - common name (e.g., virtual.domain.tld)
# $2 - certificate type (e.g., "server" or "e-mail"
generate_cert() {
	heading "Generating and signing SSL certificate for $1 ..."

	# Check if the CA directory structure has been initialized
	if [[ ! -a $ca_dir/index.txt ]]; then
		message "Generating CA directory structure..."
		pushd $ca_dir
		touch index.txt
		# Make directories if they do not exist yet (note: we assume
		# that a 'private' directory is present, which should contain
		# the CA's private key already)
		mkdir -p newcerts crl certs
		popd
	fi
	if [[ ! -a $ca_dir/serial ]]; then
		echo "01" > $ca_dir/serial
	fi

	# Generate a configuration file for OpenSSL
	local cert_type="server, email"; [[ "$2" ]] && local cert_type="$2"
	tee "$0.openssl" >/dev/null <<-EOF
		HOME   = .
		RANDFILE  = \$ENV::HOME/.rnd

		[ ca ]
		default_ca = CA_default  # The default ca section

		[ CA_default ]
		dir                    = $ca_dir
		certs                  = \$dir/certs
		crl_dir                = \$dir/crl
		database               = \$dir/index.txt
		new_certs_dir          = \$dir/newcerts
		certificate            = \$certs/$ca_name.pem
		private_key            = \$dir/private/$ca_name.key
		serial                 = \$dir/serial
		crlnumber              = \$dir/crlnumber 
		crl                    = \$dir/crl.pem  
		RANDFILE               = \$dir/private/.rand # private random number file
		x509_extensions        = usr_cert  # The extentions to add to the cert
		name_opt               = ca_default  # Subject Name options
		cert_opt               = ca_default  # Certificate field options
		default_days           = $cert_days
		default_crl_days       = 30
		default_md             = default
		preserve               = no	
		policy                 = policy_anything
		unique_subject         = no

		[ policy_anything ]
		countryName            = optional
		stateOrProvinceName    = optional
		localityName           = optional
		organizationName       = optional
		organizationalUnitName = optional
		commonName             = supplied
		emailAddress           = optional

		[ req ]
		prompt                 = no
		default_bits           = 1024
		default_keyfile        = privkey.pem
		distinguished_name     = req_distinguished_name
		x509_extensions        = v3_ca # The extentions to add to the self signed cert
		string_mask            = utf8only

		[ req_distinguished_name ]
		countryName            = $cert_country
		stateOrProvinceName    = $cert_state
		localityName           = $cert_city
		0.organizationName     = $cert_org
		organizationalUnitName = $cert_ou
		commonName             = $1
		emailAddress           = ca@$server_fqdn

		[ usr_cert ]
		basicConstraints=CA:FALSE
		nsCertType             = $cert_type
		# This will be displayed in Netscape's comment listbox.
		nsComment              = "OpenSSL Generated Certificate"
		subjectKeyIdentifier   = hash
		authorityKeyIdentifier = keyid,issuer

		[ v3_req ]
		basicConstraints       = CA:FALSE
		keyUsage = nonRepudiation, digitalSignature, keyEncipherment

		[ v3_ca ]
		subjectKeyIdentifier   = hash
		authorityKeyIdentifier = keyid:always,issuer
		basicConstraints       = CA:true

		[ crl_ext ]
		authorityKeyIdentifier = keyid:always
		EOF
	local filename=`echo $1 | sed "s/^\*\./wildcard./"`
	openssl req -config "$0.openssl" -new -nodes \
		-keyout "$filename.key" -out "$filename.csr" 
	if [[ -a "$filename.csr" ]]; then
		openssl ca  -config "$0.openssl" -batch -in "$filename.csr" -out "$filename.pem" 
		rm "$0.openssl" "$filename.csr"
		chmod 444 "$filename.pem"
		chmod 400 "$filename.key"
		rsync -v "$filename.pem" "$filename.key" $user@$server_fqdn:
	else
		message "Failed to generate certificate signing request for $1."
		exit 3
	fi
	rm -f "$filename.key" "$filename.pem" 2>&1 >/dev/null
}


# #######################################################################
# Begin configuration
# #######################################################################

if [[ $(whoami) == "root" ]]; then
	echo "Please do not run this script as root. The script will sudo commands as necessary."
	exit 1
fi

heading "This will configure the Ubuntu server. ***"


# ########################################################################
# Find out about the current environment
# ########################################################################

# if this is the server, the script should be executed in an SSH
# if no SSH is found, try to find out if is a server running in
# a VirtualBox. 
if [ -z "$SSH_CLIENT" ]; then
	# Use virt-what to determine if we are running in a virtual machine.
	install virt-what

	heading "Requesting sudo password to find out about virtual environment..."
	vm=`sudo virt-what`
	if [ "$vm" == 'virtualbox' ]; then
		heading "Running in a VirtualBox VM."
		if [ ! -d /opt/VBoxGuestAdditions* ]; then
			heading "Installing guest additions... (please have CD virtually inserted)"
			sudo mount /dev/sr0 /media/cdrom
			if [ $? -eq 0 ]; then
				install dkms build-essential
				sudo /media/cdrom/VBoxLinuxAdditions.run
			else
				heading "Could not mount guest additions cd -- exiting..."
				exit 1
			fi
		else
			heading "VirtualBox guest additions are installed."
		fi
	else # not running in a Virtual Box
		
		heading "You appear to be on a remote desktop computer."
		echo "Configured remote: $bold$user@$server_fqdn$normal"
		yesno "Synchronize the script with the one on the server?" answer y
		if (( $? )); then
			message "Updating..."
			sync_script
			code=$?
			if (( code )); then
				message "An error occurred (rsync exit code: $code). Bye."
				exit 3
			fi
			if (( $?==0 )); then
				if [[ -d "$ca_dir" ]]; then
					yesno "Generate SSL certificates and copy them to server?" answer y
					if (( $? )); then 
						generate_cert *.$domain.$tld
						generate_cert $domain.$tld
						if [[ ! $domain.$tld==$server_fqdn ]]; then
							generate_cert $server_fqdn
						fi
						if [[ -n $horde_subdomain ]]; then
							generate_cert $horde_subdomain.$server_fqdn
						fi
						rsync $ca_dir/certs/$ca_name.pem $user@$server_fqdn:.
					fi
				fi
				yesno "Log into secure shell?" answer y
				if (( $? )); then
					heading "Logging into server's secure shell..."
					ssh $user@$server_fqdn
					message "Returned from SSH session."
					sync_script
					exit 
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
	fi
else
	message "Running in a secure shell on the server."
fi


# #####################################################################
# Now let's configure the server. 
# Everything below this comment should only be executed on a running
# server. (The above parts of the script should make sure this is the
# case.)
# #####################################################################

# Look for SSL certificates in the current directory; if there are
# any, assume that the 'desktop' part of the script copied them here,
# and move them to the appropriate directory.
if [[ $(find . -name '*.pem') ]]; then
	heading "Detected SSL certificates -- moving them to /etc/ssl/certs..."
	sudo mv *.pem /etc/ssl/certs
	sudo chown root:root *.key
	sudo chmod 0400 *.key
	sudo mv *.key /etc/ssl/private
fi

# Install required packages
install dovecot-postfix dovecot-ldap postfix-ldap postfix-pcre
install pwgen slapd ldap-utils bsd-mailx
install spamassassin clamav clamav-daemon amavisd-new phpmyadmin php-pear
install php5-ldap php5-memcache memcached php-apc
install libimage-exiftool-perl aspell aspell-de aspell-de-alt php5-imagick php5-memcache

# Internal passwords for LDAP access
postfix_ldap_pw=$(pwgen -cns 16 1)
dovecot_ldap_pw=$(pwgen -cns 16 1)
horde_ldap_pw=$(pwgen -cns 16 1)

# Configure SSH
if [[ -n $(grep -i '^AllowUsers $user' /etc/ssh/sshd_config) ]]; then
	heading "Configuring SSH to allow only $user to log in."
	sudo sed -i '/^AllowUsers/ d; s/^(PermitRootLogin.*).*$/\1no' /etc/ssh/sshd_config
	sudo tee -a /etc/ssh/sshd_config >/dev/null <<-EOF
		AllowUsers $user
		EOF
fi

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

# DIT:
# http://www.asciiflow.com/#6112247197461489368/1725253880
#                                     +----------------+
#                                     |dc=domain,dc=tld|
#                                     +----------------+
#                        +-----------+                   +-----------+
#                        |  ou=auth  |                   |  ou=users |
#                        +-----------+                   +-----------+

# Check if the LDAP backend database (hdb) already contains an ACL directive
# for Postfix. If none is found, assume that we need to configure the backend
# database.
if [[ -z $(sudo ldapsearch -LLL -Y EXTERNAL -H ldapi:/// -s one \
	-b "olcDatabase={1}hdb,cn=config" "olcAccess=*postfix*" dn 2>/dev/null ) ]]
then
	# Add the schema, ACLs and first user account to LDAP.
	# Be aware that LDAP is picky about leading space!

	message "Adding access control lists (ACLs) to LDAP backend database..."
	# Ubuntu pre-configures the OpenLDAP online configuration such
	# that it is accessible as the system root, therefore we sudo
	# the following command.
	sudo ldapmodify -Y EXTERNAL -H ldapi:/// -c <<EOF
# Configure ACLs for the hdb backend database.
# Note: Continued lines MUST have a trailing space; continuation lines
# MUST have a leading space.
# First, remove the existing ACLs
dn: olcDatabase={1}hdb,cn=config
changetype: modify
delete: olcAccess

# Then, add our own ACLs
# (Note that we cannot use "-" lines here, because the entire operation would
# fail if an olcAccess attribute had not been present already.
dn: olcDatabase={1}hdb,cn=config
changetype: modify
add: olcAccess
#olcAccess: to dn.children=$ldapusersDN 
# by dn=$hordeDN manage break
# Passwords may only be accessed for authentication, or modified by the 
# correponsing users and admin.
olcAccess: to attrs=userPassword 
 by dn=$adminDN manage 
 by dn=$dovecotDN read 
 by anonymous auth 
 by self write 
 by * none
# Only admin may write to the uid, mail, and maildrop fields
# Postfix can look up these attributes
olcAccess: to attrs=uid,mail,maildrop 
 by dn=$adminDN manage 
 by self read 
 by users read 
 by dn=$postfixDN read 
 by * none
# An owner of an entry may modify it (and so may the admin);
# deny read access to non-authenticated entities
olcAccess: to * 
 by self write 
 by users read 
 by * none

dn: olcDatabase={1}hdb,cn=config
changetype: modify
add: olcDbIndex
olcDbIndex: uid pres
EOF
else
	message "LDAP ACLs already configured..."
fi


# Add courier-authlib-ldap schema:
# Converted from authldap.schema to cn=config format by D. Kraus, 29-Jul-12
# See $homepage
# Original file extracted from:
# http://de.archive.ubuntu.com/ubuntu/pool/universe/c/courier-authlib/courier-authlib-ldap_0.63.0-4build1_amd64.deb
# Line breaks were removed on purpose, as strange errors occurred on import.
# Depends on: nis.schema, which depends on cosine.schema
if [[ -z $(sudo ldapsearch -LLL -Y external -H ldapi:/// \
	-b "cn=schema,cn=config" "cn=*authldap*" dn 2>/dev/null ) ]]
then
	heading "Adding authldap schema to LDAP directory..."
	sudo ldapadd -Y EXTERNAL -H ldapi:/// -c <<EOF
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
else
	message "authldap schema already imported into LDAP."
fi

if [[ -z $(sudo ldapsearch -LLL -Y external -H ldapi:/// \
	-b "cn=config" "cn=*olcLog*" dn 2>/dev/null ) ]]
then
	heading "Enabling slapd logging..."
	sudo ldapmodify -Y EXTERNAL -H ldapi:/// -c <<EOF
dn: cn=config
changetype: modify
replace: olcLogLevel
olcLogLevel: conns stats stats2
EOF
else
	message "slapd logging already configured."
fi

heading "Binding to LDAP directory..."
echo "For binding to the LDAP directory, please enter the password that you used"
echo "during installation of this server."
code=-1
until (( $code==0 )); do
	read -sp "LDAP password for $adminDN: " ldap_admin_pw
	if [[ $ldap_admin_pw ]]; then
		ldapsearch -LLL -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// \
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

if [[ -z $(ldapsearch -LLL -w $ldap_admin_pw -D "$adminDN" -b "$ldapusersDN" "uid=$user" uid) ]]
then
	message "Adding an entry for user $user to the LDAP tree..."
	ldapadd -c -x -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// <<-EOF
		dn: $ldapusersDN
		ou: users
		objectClass: organizationalUnit

		dn: uid=$user,$ldapusersDN
		objectClass: inetOrgPerson
		objectClass: CourierMailAlias
		objectClass: CourierMailAccount
		uid: $user
		sn: $(echo $full_user_name | sed 's/^.* //')
		cn: $full_user_name
		mail: $mail
		maildrop: root
		maildrop: postmaster
		maildrop: webmaster
		maildrop: abuse
		# The homeDirectory attribute is required by the schema, but we leave
		# it empty since we are going to use $vmailhome as the uniform base
		# for all accounts.
		homeDirectory: 
		EOF
	ldappasswd -x -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// \
		-s "$pw" "uid=$user,$ldapusersDN"
else
	message "User $user already has an LDAP entry under $ldapusersDN."
fi

message "Adding/replacing LDAP entries for the Dovecot and Postfix proxy users..."
ldapadd -c -x -w $ldap_admin_pw -D "$adminDN" <<-EOF
	dn: $postfixDN
	changetype: delete

	dn: $dovecotDN
	changetype: delete

	dn: $hordeDN
	changetype: delete

	# ldapadd will complain if $ldapauth exists already, but we don't care
	# as we do not need to update it, we just need to make sure it's there
	dn: $ldapauthDN
	changetype: add
	ou: auth
	objectClass: organizationalUnit

	# Add updated entries for Postfix, Dovecot, and Horde
	dn: $postfixDN
	changetype: add
	objectClass: organizationalRole
	objectClass: simpleSecurityObject
	cn: postfix
	userPassword:
	description: Postfix proxy user
	
	dn: $dovecotDN
	changetype: add
	objectClass: organizationalRole
	objectClass: simpleSecurityObject
	cn: dovecot
	userPassword:
	description: Dovecot proxy user
	
	dn: $hordeDN
	changetype: add
	objectClass: organizationalRole
	objectClass: simpleSecurityObject
	cn: horde
	userPassword:
	description: Horde proxy user
	EOF
ldappasswd -x -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// -s "$postfix_ldap_pw" "$postfixDN"
ldappasswd -x -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// -s "$dovecot_ldap_pw" "$dovecotDN"
ldappasswd -x -w $ldap_admin_pw -D "$adminDN" -H ldapi:/// -s "$horde_ldap_pw"   "$hordeDN"


# ######################################################################
# Postfix configuration
# ----------------------------------------------------------------------
# NB: This assumes that postfix was included in the system installation.
# ######################################################################


# Set up spamassassin, clamav, and amavisd-new
if [[ -z $(grep -i 'ENABLED=1' /etc/default/spamassassin) ]]; then
	heading "Enabling spamassassin (including cron job for nightly updates)..."
	backup /etc/default/spamassassin
	sudo sed -i 's/^ENABLED=.$/ENABLED=1/' /etc/default/spamassassin
	sudo sed -i 's/^CRON=.$/CRON=1/' /etc/default/spamassassin
	echo "Starting spamassassin..."
	sudo service spamassassin start
fi

if [[ -z $(grep amavis $postfix_base/master.cf) ]]; then
	heading "Creating Postfix service for amavisd-new..."
	sudo tee -a $postfix_base/master.cf >/dev/null <<EOF
amavisfeed unix    -       -       n        -      2     lmtp
    -o lmtp_data_done_timeout=1200
    -o lmtp_send_xforward_command=yes
    -o disable_dns_lookups=yes
    -o max_use=20
127.0.0.1:10025 inet n    -       n       -       -     smtpd
    -o content_filter=
    -o smtpd_delay_reject=no
    -o smtpd_client_restrictions=permit_mynetworks,reject
    -o smtpd_helo_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o smtpd_data_restrictions=reject_unauth_pipelining
    -o smtpd_end_of_data_restrictions=
    -o smtpd_restriction_classes=
    -o mynetworks=127.0.0.0/8
    -o smtpd_error_sleep_time=0
    -o smtpd_soft_error_limit=1001
    -o smtpd_hard_error_limit=1000
    -o smtpd_client_connection_count_limit=0
    -o smtpd_client_connection_rate_limit=0
    -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks,no_milters
    -o local_header_rewrite_clients=
EOF
else
	message "Postfix service for amavisd-new already exists."
fi

if [[ -z $(grep amavis $postfix_main) ]]; then
	heading "Setting global content filter for amavisd-new in Postfix..."
	sudo postconf -e "content_filter=amavisfeed:[127.0.0.1]:10024"
else
	message "Global content filter in Postfix already set."
fi

if [[ -z $(groups clamav | grep amavis) ]]; then
	heading "Adding clamav user to amavis group..."
	sudo adduser clamav amavis
else
	message "clamav is a member of the amavis group already."
fi

if [[ ! -a /etc/amavis/conf.d/99-custom ]]; then
	heading "Adding custom configuration for amavisd-new..."
	sudo tee /etc/amavis/conf.d/99-custom >/dev/null <<'EOF'
use strict;

@bypass_virus_checks_maps = (
   \%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);

@bypass_spam_checks_maps = (
   \%bypass_spam_checks, \@bypass_spam_checks_acl, \$bypass_spam_checks_re);

# Always add spam info header
$sa_tag_level_deflt  = undef;
$sa_tag2_level_deflt = 5;
$sa_kill_level_deflt = 20;

1;  # ensure a defined return
EOF
else
	message "Custom configuration for amavisd-new already exists."
fi

# Configure Postfix to use LDAP maps
if [[ ! -a $postfix_base/postfix-ldap-aliases.cf ]]; then
	heading "Configuring Postfix to use LDAP maps for alias lookup..."
	sudo tee $postfix_base/postfix-ldap-aliases.cf > /dev/null <<-EOF
		# Postfix LDAP map generated by $(basename $0)
		# See $homepage
		# $(date --rfc-3339=seconds)

		server_host = ldapi:///

		bind = yes
		bind_dn = $postfixDN
		bind_pw = $postfix_ldap_pw

		search_base = $ldapusersDN

		# Use the %u parameter to search for the local part of an
		# email address only. %s would search for the entire string.
		query_filter = (&(objectClass=CourierMailAlias)(maildrop=%u))

		# The result_format uses %u to return the local part of an
		# address. To use virtual domains, replace %u with %s
		result_format = %u
		result_attribute = uid
		EOF
	sudo chgrp postfix $postfix_base/postfix-ldap-aliases.cf 
	sudo chmod 640     $postfix_base/postfix-ldap-aliases.cf 

	# Configure postfix to look up 'virtual' aliases. Keep in mind
	# that virtual_alias_maps is for address rewriting on receiving
	# mails, while alias_maps is for address rewriting on delivering
	# mails. Since we do not use Postfix' "local" service for 
	# delivery (but Dovecot instead), virtual_maps will never be
	# consulted in our setup.
	sudo postconf -e "virtual_alias_maps=proxy:ldap:$postfix_base/postfix-ldap-aliases.cf"
	restart_postfix=1
fi

# The Postfix password must be updated, because it was updated in the LDAP
# entry as well.
sudo sed -i -r "s/^(bind_pw =).*$/\1 $postfix_ldap_pw/" $postfix_base/postfix-ldap-aliases.cf

if [[ ! -a $postfix_base/postfix-ldap-local-recipients.cf ]]; then
	heading "Configuring Postfix to use LDAP maps for local recipient lookup..."
	sudo tee $postfix_base/postfix-ldap-local-recipients.cf > /dev/null <<-EOF
		# Postfix LDAP map generated by $(basename $0)
		# See $homepage

		server_host = ldapi:///
		bind = yes
		bind_dn = $postfixDN
		bind_pw = $postfix_ldap_pw

		search_base = $ldapusersDN
		query_filter = (&(objectClass=CourierMailAlias)(|(uid=%u)(mail=%u)))
		result_attribute = uid
		EOF
	sudo chgrp postfix $postfix_base/postfix-ldap-local-recipients.cf 
	sudo chmod 640     $postfix_base/postfix-ldap-local-recipients.cf 

	sudo postconf -e "local_recipient_maps=proxy:ldap:$postfix_base/postfix-ldap-local-recipients.cf"
	restart_postfix=1
fi
# The Postfix password must be updated, because it was updated in the LDAP
# entry as well.
sudo sed -i -r "s/^(bind_pw =).*$/\1 $postfix_ldap_pw/" \
	$postfix_base/postfix-ldap-local-recipients.cf


if [[ ! -a $postfix_base/postfix-ldap-canonical-map.cf ]]; then
	heading "Configuring Postfix to use LDAP maps for local recipient lookup..."
	sudo tee $postfix_base/postfix-ldap-canonical-map.cf > /dev/null <<-EOF
		# Postfix LDAP map for canonical names generated by $(basename $0)
		# See $homepage

		server_host = ldapi:///
		bind = yes
		bind_dn = $postfixDN
		bind_pw = $postfix_ldap_pw

		search_base = $ldapusersDN
		query_filter = (&(objectClass=CourierMailAlias)(uid=%u))
		result_attribute = mail
		EOF
	sudo chgrp postfix $postfix_base/postfix-ldap-canonical-map.cf 
	sudo chmod 640     $postfix_base/postfix-ldap-canonical-map.cf 

	sudo postconf -e "canonical_maps = proxy:ldap:$postfix_base/postfix-ldap-canonical-map.cf"
	sudo postconf -e "canonical_classes = header_recipient, header_sender, envelope_recipient, envelope_sender"
	sudo postconf -e "local_header_rewrite_clients = static:all"
	restart_postfix=1
fi
# The Postfix password must be updated, because it was updated in the LDAP
# entry as well.
sudo sed -i -r "s/^(bind_pw =).*$/\1 $postfix_ldap_pw/" \
	$postfix_base/postfix-ldap-canonical-map.cf


if [[ -z $(grep dovecot $postfix_base/master.cf) ]]; then
	heading "Declaring Dovecot transport Postfix master..."
	backup $postfix_base/master.cf
	sudo tee -a $postfix_base/master.cf > /dev/null <<EOF
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=$vmailuser:$vmailuser argv=/usr/lib/dovecot/deliver -f \${sender} -d \${recipient}
EOF
	restart_postfix=1
fi

if [[ -z $(grep "local_transport = dovecot" $postfix_main) ]]; then
	heading "Configuring Postfix' local transport to use dovecot pipe..."
	sudo postconf -e "dovecot_destination_recipient_limit = 1"
	sudo postconf -e "local_transport = dovecot"
	# Comment out the mailbox_command directive:
	sudo sed -i 's/^mailbox_command/#&/' $postfix_main
	restart_postfix=1
fi

# Require fully qualified HELO -- this requirement (though RFC2821 conformant)
# may not be met by Outlook and Outlook Express.
# sudo postconf -e "smtpd_helo_required = yes"

# The following restrictions may be made more tight by adding:
#	reject_unknown_sender_domain \
# after 'reject_non_fqdn_sender'. Note however that this will cause all e-mails
# from your local, non-DNS-registered test domain to be rejected.
sudo sed -i '/^smtpd_recipient_restrictions/ d' $postfix_main
sudo tee -a $postfix_main >/dev/null <<EOF
smtpd_recipient_restrictions = 
	reject_non_fqdn_recipient,
	reject_non_fqdn_sender,
	reject_unknown_recipient_domain,
	permit_mynetworks,
	reject_sender_login_mismatch,
	reject_unauth_destination,
	check_recipient_access hash:$postfix_base/roleaccount_exceptions,
	reject_multi_recipient_bounce,
	reject_non_fqdn_hostname,
	reject_invalid_hostname,
	check_helo_access pcre:$postfix_base/helo_checks,
	check_sender_mx_access cidr:$postfix_base/bogus_mx,
	permit
EOF

sudo tee $postfix_base/roleaccount_exceptions >/dev/null <<-EOF
	postmaster@  OK
	abuse@       OK
	hostmaster@  OK
	webmaster@   OK
	EOF
sudo postmap hash:/$postfix_base/roleaccount_exceptions

sudo tee $postfix_base/helo_checks >/dev/null <<-EOF
	/^$(echo $server_fqdn | sed 's/\./\\./g')\$/    550 Don't use my hostname
	/^$(echo $ip | sed 's/\./\\./g')\$/             550 Don't use my IP address
	/^\[$(echo $ip | sed 's/\./\\./g')\]\$/         550 Don't use my IP address
	EOF

sudo tee $postfix_base/bogus_mx >/dev/null <<-EOF
	# bogus networks
	0.0.0.0/8       550 Mail server in broadcast network
	10.0.0.0/8      550 No route to your RFC 1918 network
	127.0.0.0/8     550 Mail server in loopback network
	224.0.0.0/4     550 Mail server in class D multicast network
	172.16.0.0/12   550 No route to your RFC 1918 network
	192.168.0.0/16  550 No route to your RFC 1918 network
	# spam havens
	69.6.0.0/18     550 REJECT Listed on Register of Known Spam Operations
	# Wild-card MTA
	64.94.110.11/32 550 REJECT VeriSign domain wildcard
	EOF

# #######################################################################
# Dovecot configuration
# #######################################################################

# Relax permissions of Dovecot's auth-userdb socket (required when dovecot-lda
# is used for local mail delivery).
# The following sed command will adjust the mode, user, and group directives
# for auth-userdb.
if [[ $(grep -Pzo "auth-userdb.*\N\s*?#mode" $dovecot_confd/10-master.conf) ]]; then
	heading "Adjusting permissions of  Dovecot's auth-userdb socket..."
	sudo sed -i -r "/auth-userdb \{/,/}/ { \
		s/^(\s*)#mode = 0600.*$/\1mode = 0660/; \
		s/^(\s*)#user =.*$/\1user = $vmailuser/; \
		s/^(\s*)#group =.*$/\1group = $vmailuser/ ;}" $dovecot_confd/10-master.conf
	restart_dovecot=1
else
	message "Dovecot's auth-userdb socket permissions already adjusted."
fi

if [[ -n $(grep '#!include auth-ldap' $dovecot_confd/10-auth.conf) ]]; then
	pushd $dovecot_confd
	backup 10-auth.conf auth-ldap.conf.ext
	heading "Configuring Dovecot to look up users and passwords in LDAP directory..."
	sudo tee auth-ldap.conf.ext >/dev/null <<EOF
# Authentication for LDAP users. Included from auth.conf.
# Automagically generated by $(basename $0)
# See $homepage
# $(date --rfc-3339=seconds)

passdb {
  driver = ldap
  args = $dovecot_base/dovecot-ldap.conf.ext
}

userdb {
 driver = static
 args = uid=$vmailuser gid=$vmailuser home=$vmailhome/%Ln
}
EOF
	sudo sed -i -r 's/^#?(!include auth)/#\1/'           10-auth.conf
	sudo sed -i -r 's/^#(!include auth-ldap)/\1/'        10-auth.conf
	sudo sed -i -r "s/^#?(mail_.id =).*$/\1 $vmailuser/" 10-mail.conf
	cd $dovecot_base
	backup dovecot-ldap.conf.ext
	sudo tee dovecot-ldap.conf.ext >/dev/null <<-EOF
		# Dovecot LDAP configuration generated by $(basename $0)
		# See $homepage
		# $(date --rfc-3339=seconds)
		uris = ldapi:///
		dn = $dovecotDN
		dnpass = $dovecot_ldap_pw

		#sasl_bind = yes
		#sasl_mech =
		#sasl_realm =

		#tls = yes
		#tls_ca_cert_file =
		#tls_ca_cert_dir =
		#tls_cipher_suite =

		#debug_level = -1

		# We don't do authentication binds for lookups, therefore 'no'
		auth_bind = no
		base = $ldapusersDN
		#deref = never
		pass_attrs = uid=user,userPassword=password

		# Change %Ln to %u if you want user IDs with domain
		# Since Postfix rewrites the envelope recipient to the canonical
		# mail address (mail attribute in LDAP entry), we need to search
		# for %Ln in 'mail' also.
		pass_filter = (&(objectClass=inetOrgPerson)(|(uid=%Ln)(mail=%Ln))

		#default_pass_scheme = SSHA

		# Attributes and filter to get a list of all users
		#iterate_attrs = uid=user
		#iterate_filter = (objectClass=inetOrgPerson)
		EOF
	sudo chmod 600 dovecot-ldap.conf.ext
	popd
	restart_dovecot=1
else
	heading "Dovecot custom configuration already present."
fi

# The Dovecot password must be updated, because it was updated in the LDAP
# entry as well.
sudo sed -i -r "s/^(dnpass =).*$/\1 $dovecot_ldap_pw/" $dovecot_base/dovecot-ldap.conf.ext

# Add the vmail user.
# No need to make individual user's directories as Dovecot will
# take care of this.
if [[ -z $(id $vmailuser) ]]; then
	heading "Adding vmail user..."
	sudo adduser --system --home $vmailhome --uid 5000 --group $vmailuser
	sudo chown $vmailuser:$vmailuser $vmailhome
	sudo chmod -R 750 $vmailhome
else
	heading "User $vmailuser already exists."
fi

# Configure SSL/TLS for the mail suite
# dovecot-postfix already did some work for us, so that we only need to
# adjust symlinks.
heading "Updating SSL certificate paths..."
if [[ "$server_fqdn"=="$domain.$tld" ]]; then
	sudo ln -sf /etc/ssl/certs/$server_fqdn.pem   /etc/ssl/certs/ssl-mail.pem
	sudo ln -sf /etc/ssl/private/$server_fqdn.key /etc/ssl/private/ssl-mail.key
	sudo ln -sf /etc/ssl/certs/$server_fqdn.pem   /etc/ssl/certs/dovecot.pem
	sudo ln -sf /etc/ssl/private/$server_fqdn.key /etc/ssl/private/dovecot.pem
else
	sudo ln -sf /etc/ssl/certs/wildcard.$domain.$tld.pem   /etc/ssl/certs/ssl-mail.pem
	sudo ln -sf /etc/ssl/private/wildcard.$domain.$tld.key /etc/ssl/private/ssl-mail.key
	sudo ln -sf /etc/ssl/certs/wildcard.$domain.$tld.pem   /etc/ssl/certs/dovecot.pem
	sudo ln -sf /etc/ssl/private/wildcard.$domain.$tld.key /etc/ssl/private/dovecot.pem
fi

# Lastly, restart Postfix and Dovecot
if (( restart_postfix+restart_dovecot )); then 
	heading "Restarting services..."
fi
if (( restart_postfix )); then sudo service postfix restart; fi
if (( restart_dovecot )); then sudo service dovecot restart; fi


# ######################
# PHPmyadmin
# ######################

if [[ ! $(grep ForceSSL /etc/phpmyadmin/config.inc.php) ]]; then
	echo "\$cfg['ForceSSL']=true;" | \
		sudo tee -a /etc/phpmyadmin/config.inc.php > /dev/null
fi


# ######################
# Horde configuration
# ######################

if [[ ! -d $horde_dir ]]; then
	heading "Installing Horde..."
	sudo pear channel-discover pear.horde.org
	sudo pear install horde/horde_role
	sudo pear run-scripts horde/horde_role
	sudo pear install horde/webmail
	sudo pear install horde/Horde_Ldap
	mysql -u$mysqladmin -p -e "create database $horde_database;"
	sudo webmail-install
	sudo chown www-mail:www-mail $horde_dir
else
	heading "Horde already installed."
fi

# Adjust horde configuration
heading "Adjusting horde configuration..."
# sudo sed -i -r "s/^(.conf..ldap....bindpw.*=.).*$/\1'$horde_ldap_pw';/" $horde_dir/config/conf.php
read -sp "Please enter the MySQL password for $mysqladmin: " mysql_admin_pw

# Extract the local horde's secret key
horde_secret_key=`grep -o -E '.{8}-.{4}-.{4}-.{4}-.{12}' /$horde_dir/config/conf.php`

sudo tee $horde_dir/config/conf.php >/dev/null <<-EOF
	<?php
	/* CONFIG START. DO NOT CHANGE ANYTHING IN OR AFTER THIS LINE. */
	// $Id: 7132f71317ff8b99212d581514435cc9765c7a9e $
	\$conf['vhosts'] = false;
	\$conf['debug_level'] = E_ALL & ~E_NOTICE;
	\$conf['max_exec_time'] = 0;
	\$conf['compress_pages'] = true;
	\$conf['secret_key'] = '$horde_secret_key';
	\$conf['umask'] = 077;
	\$conf['testdisable'] = true;
	\$conf['use_ssl'] = 2;
	\$conf['server']['name'] = \$_SERVER['SERVER_NAME'];
	\$conf['urls']['token_lifetime'] = 30;
	\$conf['urls']['hmac_lifetime'] = 30;
	\$conf['urls']['pretty'] = false;
	\$conf['safe_ips'] = array();
	\$conf['session']['name'] = 'Horde';
	\$conf['session']['use_only_cookies'] = true;
	\$conf['session']['cache_limiter'] = 'nocache';
	\$conf['session']['timeout'] = 0;
	\$conf['cookie']['domain'] = \$_SERVER['SERVER_NAME'];
	\$conf['cookie']['path'] = '/';
	\$conf['sql']['username'] = '$mysqladmin';
	\$conf['sql']['password'] = '$mysql_admin_pw';
	\$conf['sql']['protocol'] = 'unix';
	\$conf['sql']['database'] = 'horde';
	\$conf['sql']['charset'] = 'utf-8';
	\$conf['sql']['ssl'] = true;
	\$conf['sql']['splitread'] = false;
	\$conf['sql']['phptype'] = 'mysqli';
	\$conf['ldap']['hostspec'] = 'localhost';
	\$conf['ldap']['tls'] = false;
	\$conf['ldap']['version'] = 3;
	\$conf['ldap']['binddn'] = '$hordeDN';
	\$conf['ldap']['bindpw'] = '$horde_ldap_pw';
	\$conf['ldap']['bindas'] = 'admin';
	\$conf['ldap']['useldap'] = true;
	\$conf['auth']['admins'] = array('$user');
	\$conf['auth']['checkip'] = true;
	\$conf['auth']['checkbrowser'] = true;
	\$conf['auth']['resetpassword'] = true;
	\$conf['auth']['alternate_login'] = false;
	\$conf['auth']['redirect_on_logout'] = false;
	\$conf['auth']['list_users'] = 'list';
	\$conf['auth']['params']['basedn'] = '$ldapusersDN';
	\$conf['auth']['params']['scope'] = 'sub';
	\$conf['auth']['params']['ad'] = false;
	\$conf['auth']['params']['uid'] = 'uid';
	\$conf['auth']['params']['encryption'] = 'ssha';
	\$conf['auth']['params']['newuser_objectclass'] = array('inetOrgPerson', 'CourierMailAccount', 'CourierMailAlias');
	\$conf['auth']['params']['filter'] = '(objectclass=CourierMailAccount)';
	\$conf['auth']['params']['password_expiration'] = 'no';
	\$conf['auth']['params']['driverconfig'] = 'horde';
	\$conf['auth']['driver'] = 'ldap';
	\$conf['auth']['params']['count_bad_logins'] = false;
	\$conf['auth']['params']['login_block'] = false;
	\$conf['auth']['params']['login_block_count'] = 5;
	\$conf['auth']['params']['login_block_time'] = 5;
	\$conf['signup']['params']['driverconfig'] = 'horde';
	\$conf['signup']['driver'] = 'Sql';
	\$conf['signup']['approve'] = true;
	\$conf['signup']['allow'] = true;
	\$conf['log']['priority'] = 'WARNING';
	\$conf['log']['ident'] = 'HORDE';
	\$conf['log']['name'] = LOG_USER;
	\$conf['log']['type'] = 'syslog';
	\$conf['log']['enabled'] = true;
	\$conf['log_accesskeys'] = false;
	\$conf['prefs']['params']['driverconfig'] = 'horde';
	\$conf['prefs']['driver'] = 'Sql';
	\$conf['alarms']['params']['driverconfig'] = 'horde';
	\$conf['alarms']['params']['ttl'] = 300;
	\$conf['alarms']['driver'] = 'Sql';
	\$conf['datatree']['driver'] = 'null';
	\$conf['group']['driverconfig'] = 'horde';
	\$conf['group']['driver'] = 'Sql';
	\$conf['perms']['driverconfig'] = 'horde';
	\$conf['perms']['driver'] = 'Sql';
	\$conf['share']['no_sharing'] = false;
	\$conf['share']['auto_create'] = true;
	\$conf['share']['world'] = true;
	\$conf['share']['any_group'] = false;
	\$conf['share']['hidden'] = false;
	\$conf['share']['cache'] = false;
	\$conf['share']['driver'] = 'Sqlng';
	\$conf['cache']['default_lifetime'] = 86400;
	\$conf['cache']['params']['sub'] = 0;
	\$conf['cache']['driver'] = 'File';
	\$conf['cache']['compress'] = true;
	\$conf['cache']['use_memorycache'] = '';
	\$conf['cachecssparams']['driver'] = 'filesystem';
	\$conf['cachecssparams']['lifetime'] = 86400;
	\$conf['cachecssparams']['compress'] = 'php';
	\$conf['cachecss'] = true;
	\$conf['cachejsparams']['driver'] = 'filesystem';
	\$conf['cachejsparams']['compress'] = 'php';
	\$conf['cachejsparams']['lifetime'] = 86400;
	\$conf['cachejs'] = true;
	\$conf['cachethemesparams']['check'] = 'appversion';
	\$conf['cachethemesparams']['lifetime'] = 604800;
	\$conf['cachethemes'] = true;
	\$conf['lock']['params']['driverconfig'] = 'horde';
	\$conf['lock']['driver'] = 'Sql';
	\$conf['token']['params']['driverconfig'] = 'horde';
	\$conf['token']['driver'] = 'Sql';
	\$conf['mailer']['params']['auth'] = false;
	\$conf['mailer']['type'] = 'smtp';
	\$conf['mailformat']['brokenrfc2231'] = false;
	\$conf['vfs']['params']['driverconfig'] = 'horde';
	\$conf['vfs']['type'] = 'Sql';
	\$conf['sessionhandler']['type'] = 'Builtin';
	\$conf['sessionhandler']['memcache'] = false;
	\$conf['spell']['params']['path'] = '/usr/bin/aspell';
	\$conf['spell']['driver'] = 'aspell';
	\$conf['gnupg']['keyserver'] = array('pool.sks-keyservers.net');
	\$conf['gnupg']['timeout'] = 10;
	\$conf['openssl']['cafile'] = '/etc/ssl/certs';
	\$conf['openssl']['path'] = '/usr/bin/openssl';
	\$conf['nobase64_img'] = false;
	\$conf['image']['driver'] = 'Imagick';
	\$conf['exif']['params']['exiftool'] = '/usr/bin/exiftool';
	\$conf['exif']['driver'] = 'Exiftool';
	\$conf['problems']['email'] = 'webmaster@$server_fqdn';
	\$conf['problems']['maildomain'] = '$server_fqdn';
	\$conf['problems']['tickets'] = false;
	\$conf['problems']['attachments'] = true;
	\$conf['menu']['apps'] = array();
	\$conf['menu']['always'] = false;
	\$conf['menu']['links']['help'] = 'all';
	\$conf['menu']['links']['prefs'] = 'authenticated';
	\$conf['menu']['links']['problem'] = 'all';
	\$conf['menu']['links']['login'] = 'all';
	\$conf['menu']['links']['logout'] = 'authenticated';
	\$conf['portal']['fixed_blocks'] = array();
	\$conf['accounts']['params']['basedn'] = '$ldapusersDN';
	\$conf['accounts']['params']['scope'] = 'sub';
	\$conf['accounts']['params']['attr'] = 'uid';
	\$conf['accounts']['params']['strip'] = true;
	\$conf['accounts']['params']['driverconfig'] = 'horde';
	\$conf['accounts']['driver'] = 'ldap';
	\$conf['user']['verify_from_addr'] = true;
	\$conf['user']['select_view'] = true;
	\$conf['facebook']['enabled'] = false;
	\$conf['twitter']['enabled'] = false;
	\$conf['urlshortener'] = 'TinyUrl';
	\$conf['weather']['params']['lifetime'] = 21600;
	\$conf['weather']['provider'] = 'Google';
	\$conf['imsp']['enabled'] = false;
	\$conf['kolab']['enabled'] = false;
	\$conf['memcache']['hostspec'] = array('localhost');
	\$conf['memcache']['port'] = array('11211');
	\$conf['memcache']['weight'] = array();
	\$conf['memcache']['persistent'] = false;
	\$conf['memcache']['compression'] = false;
	\$conf['memcache']['large_items'] = true;
	\$conf['memcache']['enabled'] = true;
	\$conf['activesync']['enabled'] = false;
	/* CONFIG END. DO NOT CHANGE ANYTHING IN OR BEFORE THIS LINE. */
	EOF

if [[ ! -a /etc/apache2/sites-enabled/horde ]]; then
	heading "Configuring horde subdomain for apache..."
	if [[ -n $horde_subdomain ]]; then
		horde_fqdn=$horde_subdomain.$server_fqdn
	else
		horde_fqdn=$server_fqdn
	fi
	sudo tee /etc/apache2/sites-available/horde > /dev/null <<EOF
<IfModule mod_ssl.c>
<VirtualHost *:80>
	ServerName $horde_fqdn
	Redirect permanent / https://$horde_fqdn/
</Virtualhost>
<VirtualHost *:443>
	ServerAdmin webmaster@$server_fqdn
	ServerName $horde_fqdn
	DocumentRoot $horde_dir
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory $horde_dir>
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>

	ErrorLog \${APACHE_LOG_DIR}/error.log

	# Possible values include: debug, info, notice, warn, error, crit,
	# alert, emerg.
	LogLevel warn

	CustomLog \${APACHE_LOG_DIR}/ssl_access.log combined

	SSLEngine on
	SSLCertificateFile    /etc/ssl/certs/$horde_fqdn.pem
	SSLCertificateKeyFile /etc/ssl/private/$horde_fqdn.key

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
	sudo a2enmod ssl rewrite
	sudo service apache2 restart
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
