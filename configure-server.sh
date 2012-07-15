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
		echo "## Fatal: yesno() received default answer '$2', which is neither yes nor no."
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
	[ $(echo $3 | grep -i $answer) ] && return 1
}

echo $bold"This will configure the Ubuntu server."$normal

# Use virt-what to determine if we are running in a virtual machine.
if [ -z `which virt-what` ]; then
	echo $bold"Installing virt-what..."$normal
	sudo apt-get install -y virt-what
fi

echo "Requesting sudo password to find out about virtual environment..."
vm=`sudo virt-what`
if [ "$vm" == 'virtualbox' ]; then
	echo $bold"Running in a VirtualBox VM."$normal
	if [ ! -d /opt/VBoxGuestAdditions* ]; then
		echo "Installing guest additions... (please have CD virtually inserted)"$normal
		sudo mount /dev/sr0 /media/cdrom
		if [ $? -eq 0 ]; then
			sudo apt-get install dkms build-essential
			sudo /media/cdrom/VBoxLinuxAdditions.run
		else
			echo $bold"Could not mount guest additions cd -- exiting..."$normal
			exit 1
		fi
	else
		echo "VirtualBox guest additions are installed."
	fi
else # not running in a Virtual Box
	# if this is the server, the script should be executed in an SSH
	# if no SSH is found, assume that this is the remote desktop computer
	# (assuming 
	if [ -z "$SSH_CLIENT" ]; then
		echo $bold"You appear to be on a remote desktop computer."$normal
		yesno "Copy the script to the server and log into the SSH?" answer y
		if [ $? ]; then
			read -p "Please enter user name on server: " -e -i $remote_user remote_user
			read -p "Please enter server name: " -e -i $server server
			echo $bold"Copying this script to the remote user's home directory..."$normal
			scp $0 $remote_user@$server:.
			echo $bold"Logging into server using SSH..."$normal
			ssh $remote_user@$server
			exit
		fi
	else
		echo "Running in a secure shell on the server."
	fi
fi


# #####################################################################
# Now let's configure the server
# #####################################################################

# Prevent Grub from waiting indefinitely for user input on a headless server.

if [ $(grep "set timeout=-1" /etc/grub.d/00_header) ]; then
	yesno "Patch Grub to not wait for user input when booting the system?" answer y
	if [ $? ]; then
		echo $bold"Patching Grub..."$normal
		patch /etc/grub.d/00_header <<EOF
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
	echo "Grub is already patched."
fi


# vim: fo+=qn
