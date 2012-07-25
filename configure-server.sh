#!/bin/bash
bold=`tput bold`
normal=`tput sgr0`
server=bdkraus.fritz.box
remote_user=daniel

yesno() {
	# Prompts the user for a y/n choice
	# $1 - prompt
	# $2 - variable to store the answer into
	# $3 - default answer
	# Returns 0 if non-default answer, 1 if default answer.
	if [ -n $3 -a -z `echo $2 | grep -i [yn]` ]; then
		echo "### Fatal: yesno() received default answer '$2', which is neither yes nor no."
		exit 99
	fi
	local choice="yn"
	[[ $(echo $3 | grep -i y) ]] && local choice="Yn"
	[[ $(echo $3 | grep -i n) ]] && local choice="yN"
	echo -n $1" [$choice] "
	local answer=x
	until [[ -z "$answer" || $(echo $answer | grep -i [yn]) ]]; do
		read -s -n 1 answer
	done
	eval $2="$answer"
	[ -z $answer ] && eval $2="$3"
	echo $answer
	[[ $(echo $answer | grep -i $3) ]] && return 1
	return 0
}

heading() {
	echo -e $bold"\n*** $1"$normal
}


# ########################################################################
# Find out about the current environment
# ########################################################################

heading "This will configure the Ubuntu server. ***"

# Use virt-what to determine if we are running in a virtual machine.
if [ -z `which virt-what` ]; then
	heading "Installing virt-what..."
	sudo apt-get install -y virt-what
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
		yesno "Copy the script to the server and log into the SSH?" answer y
		if [[ $? ]]; then
			read -p "Please enter user name on server: " -e -i $remote_user remote_user
			read -p "Please enter server name: " -e -i $server server
			heading "Copying this script to the remote user's home directory..."
			scp $0 $remote_user@$server:.
			if [[ $? ]]; then
				heading "Logging into server using SSH..."
				ssh $remote_user@$server
			else
				echo "Failed to copy the file. Please check that the server is running "
				echo "and the credentials are correct."$normal
			fi
			exit
		fi
	else
		heading "Running in a secure shell on the server."
	fi
fi


# #####################################################################
# Now let's configure the server. 
# Everything below this comment should only be executed on a running
# server. (The above parts of the script should make sure this is the
# case.)
# #####################################################################

# Prevent Grub from waiting indefinitely for user input on a headless server.

if [ $(grep "set timeout=-1" /etc/grub.d/00_header) ]; then
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
	sudo apt-get -y install slapd lapd-utils
else
	heading "LDAP already installed."
fi

# #####################
# Postfix configuration
# #####################

# Enable system to send administrative emails
if [[ $(dpkg -s bsd-mailx 2>&1 | grep "not installed") ]]; then
	heading "Installing bsd-mailx package..."
	sudo apt-get -y install bsd-mailx
else
	heading "bsd-mailx package already installed."
fi

# Create alias for current user
if [[ ! $(grep "root: $(whoami)" /etc/aliases) ]]; then
	yesno "Create root -> $(whoami) alias?" answer y
	if (( $? )); then
		heading "Creating alias..."
		echo "root: $(whoami)" | sudo tee -a /etc/aliases
	fi
else
	heading "Mail alias for root -> $(whoami) already configured."
fi

# ######################
# PHPmyadmin
# ######################

if [[ $(dpkg -s phpmyadmin 2>&1 | grep "not installed" ) ]]; then
	heading "Installing phpMyAdmin..."
	sudo apt-get -y install phpmyadmin
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
	sudo apt-get -y install php-pear
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
	ServerAdmin webmaster@$server
	ServerName horde.$server
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

# vim: fo+=ro
