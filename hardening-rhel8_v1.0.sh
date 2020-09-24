#!/bin/bash
######################
###### FUNCTIONS #####
######################

function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

function perform_remediation {
	# test "$mount_has_to_exist" = 'yes'
	if test "yes" = 'yes'; then
		assert_mount_point_in_fstab /home || { echo "Not remediating, because there is no record of /home in /etc/fstab" >&2; return 1; }
	fi

	ensure_mount_option_in_fstab "/home" "nosuid" "" ""
    ensure_mount_option_in_fstab "/home" "nodev" "" ""
	ensure_partition_is_mounted "/home"

    ensure_mount_option_in_fstab "/var" "nodev" "" ""
	ensure_partition_is_mounted "/var"

    ensure_mount_option_in_fstab "/var/log" "nosuid" "" ""
    ensure_mount_option_in_fstab "/var/log" "nodev" "" ""
    ensure_mount_option_in_fstab "/var/log" "noexec" "" ""
	ensure_partition_is_mounted "/var/log"

    ensure_mount_option_in_fstab "/var/log/audit" "nosuid" "" ""
    ensure_mount_option_in_fstab "/var/log/audit" "nodev" "" ""
    ensure_mount_option_in_fstab "/var/log/audit" "noexec" "" ""
	ensure_partition_is_mounted "/var/log/audit"

    ensure_mount_option_in_fstab "/var/tmp" "nosuid" "" ""
    ensure_mount_option_in_fstab "/var/tmp" "nodev" "" ""
    ensure_mount_option_in_fstab "/var/tmp" "noexec" "" ""
	ensure_partition_is_mounted "/var/tmp"

    ensure_mount_option_in_fstab "/tmp" "nosuid" "" ""
    ensure_mount_option_in_fstab "/tmp" "nodev" "" ""
    ensure_mount_option_in_fstab "/tmp" "noexec" "" ""
	ensure_partition_is_mounted "/tmp"

    ensure_mount_option_in_fstab "/boot" "nosuid" "" ""
    ensure_mount_option_in_fstab "/boot" "nodev" "" ""
	ensure_partition_is_mounted "/boot"

    ensure_mount_option_in_fstab "/dev/shm" "nosuid" "tmpfs" "tmpfs"
    ensure_mount_option_in_fstab "/dev/shm" "nodev" "tmpfs" "tmpfs"
    ensure_mount_option_in_fstab "/dev/shm" "noexec" "tmpfs" "tmpfs"
    ensure_partition_is_mounted "/dev/shm"

}

###########################################
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:	Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#

function replace_or_append {


  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}

##########################
###### END FUNCTIONS #####
##########################



##################################################
######## ** 2.1 **  DISABLE INTERACTIVE BOOT ##### 
##################################################

echo "###############################################"
echo "#### ** 2.1 **	FILESYSTEM CONFIGURATION ####"
echo "###############################################"
echo 
echo "###### Disable interactive boot #####"
echo

CONFIRM_SPAWN_YES="systemd.confirm_spawn=\(1\|yes\|true\|on\)"
CONFIRM_SPAWN_NO="systemd.confirm_spawn=no"

if grep -q "\(GRUB_CMDLINE_LINUX\|GRUB_CMDLINE_LINUX_DEFAULT\)" /etc/default/grub
then
	sed -i "s/${CONFIRM_SPAWN_YES}/${CONFIRM_SPAWN_NO}/" /etc/default/grub
fi
# Remove 'systemd.confirm_spawn' kernel argument also from runtime settings
/sbin/grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"

echo 
echo "###### separate partitions and restrict partition mount options #####"
echo
perform_remediation

cat /etc/fstab 


#################################################
######## 2.2 PASSWORD QUALITY REQUIREMENTS ###### 
#################################################
echo
echo "#################################################"
echo "#### ** 2.2 ** PASSWORD QUALITY REQUIREMENTS ####"
echo "#################################################"
echo 
### Prerequisiti 
echo
echo "## Enable oddjobd service as prerequisite of authselect feature: ##"
systemctl enable oddjobd.service
systemctl start oddjobd.service
## end Prerequisiti 

echo
echo "## Backup current profile ## "
authselect apply-changes -b --backup=sssd.backup
echo
echo "## Create nuew custom profile named 'password-policy copied from existing profile sssd ## "
authselect create-profile password-policy -b sssd --symlink-meta --symlink-pam
echo
echo "## Set new custom profile as current profile ## "
authselect select custom/password-policy
authselect current
echo
echo "## Enable mkHomeDir feature: ##"
authselect enable-feature with-mkhomedir
echo
echo "## Apply changes ... ## "
authselect apply-changes

################################
### HISTORY OF USED PASSWORD ###
################################
echo
echo
echo "##### History of used Password ######"
echo
var_password_pam_unix_remember="4"

AUTH_FILES[0]="/etc/authselect/custom/password-policy/system-auth"
AUTH_FILES[1]="/etc/authselect/custom/password-policy/password-auth"

for pamFile in "${AUTH_FILES[@]}"
  do
    if ! grep -e "^password[[:space:]]\+requisite[[:space:]]\+pam_pwhistory.so.*remember=$var_password_pam_unix_remember" $pamFile; then
      sed -i.bkp  --follow-symlinks "/^password[[:space:]]\+requisite[[:space:]]\+pam_pwquality.so/a password    requisite     pam_pwhistory.so remember=$var_password_pam_unix_remember use_authok" $pamFile
    else
      echo "Entry remember=$var_password_pam_unix_remember already present in file $pamFile"
    fi
done

############################################
### Enforce root for password complexity ###
############################################
echo
echo
echo "##### Enforce root for password complexity ######"
echo
for pamFile in "${AUTH_FILES[@]}"
  do
    if ! grep -e "^password[[:space:]]\+requisite[[:space:]]\+pam_pwquality.so.*enforce_for_root" $pamFile; then
       sed -i --follow-symlinks "/^password[[:space:]]\+requisite[[:space:]]\+pam_pwquality.so/ s/$/ enforce_for_root/" $pamFile
	   echo "Set enforce_for_root for $pamFile"
    else
       echo "Entry enforce_for_root already present in $pamFile"	
    fi
done

echo 
echo "## Apply changes ... ## "
authselect apply-changes


#################################
### Configure Password Policy ###
#################################
echo
echo
echo "##### Configure Password Policy ######"
echo

replace_or_append '/etc/security/pwquality.conf' '^difok' '4' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^minlen' '9' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^dcredit' '-1' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^ucredit' '-1' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^lcredit' '-1' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^ocredit' '-1' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^maxrepeat' '3' 'Hardening Rhel8 Lottomatica' '%s = %s'
replace_or_append '/etc/security/pwquality.conf' '^minclass' '1' 'Hardening Rhel8 Lottomatica' '%s = %s'


#####################################################
### Prevent Login to Accounts With Empty Password ###
#####################################################
echo
echo
echo "##### Prevent Login to Accounts With Empty Password #####"
echo "### ** set password minimum length in login.defs ** ###"
echo
replace_or_append '/etc/login.defs' '^PASS_MIN_LEN' '9' 'Hardening Rhel8 Lottomatica' '%s %s'


############################################################
################ 2.3	SYSTEM ACCOUNTS  ###################
############################################################
###
echo
echo "#################################################"
echo "######### **2.3**	SYSTEM ACCOUNTS ** ############"
echo "#################################################"
echo 
echo "### Delete some users  that are created by the default OS installation  ###"
echo
userdel -f -r games
groupdel -f games
userdel -f -r gopher
userdel -f -r ftp
userdel -f -r news
groupdel -f news
userdel -r -f lp
userdel -r -f cockpit-ws 
userdel -r -f cockpit-wsinstance 
echo 

################################
### **2.4**	CONFIGURE SSH ** ###
################################
ssh_generic_check()
{
    PAR=$1
    VAL=$2

    ROW=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w $PAR | tail -1 `
    PARV=`echo $ROW | awk '{print $1}'`
    VALV=`echo $ROW | awk '{print $2}'`

    if [ "Z${VAL}" = "Z${VALV}" ]; then
        return 0
    else
        return 10
    fi
}
ssh_generic_change()
{
    PAR=$1
    VAL=$2
    #cp -p /etc/ssh/sshd_config /etc/ssh/.sshd_config_pre_${STE}
    sed -i "s:^${PAR}:#### hardening SSHD ### ${PAR} :g" /etc/ssh/sshd_config
    echo "${PAR} ${VAL}   # HARDENING " >> /etc/ssh/sshd_config
    /usr/sbin/sshd -t 
    if [ $? -gt 3 ]
        then
            #rollback
            #/bin/cp -pf /etc/ssh/.sshd_config_pre_${STE} /etc/ssh/sshd_config
            echo "${PAR}  non compatibile con la versione"
        else
        echo "OK: modificato valore $PAR in $VAL nel file /etc/ssh/sshd_config"
    fi

}

echo
echo "#################################################"
echo "######### **2.4**	CONFIGURE SSH ** ########"
echo "#################################################"
echo
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig.$(date '+%Y%m%d%H%M')

ssh_generic_check Protocol 2
if [ $? -eq 0 ]; then
    echo "OK: SSH Protocol versione 2"
else    
    ssh_generic_change Protocol 2
fi

echo
ssh_generic_check LogLevel INFO
if [ $? -eq 0 ]; then
    echo "OK: SSH LogLevel INFO"
else    
    ssh_generic_change LogLevel INFO
fi

echo 
ssh_generic_check MaxAuthTries 3
if [ $? -eq 0 ]; then
    echo "OK: SSH MaxAuthTries 3"
else    
    ssh_generic_change MaxAuthTries 3
fi

echo 
ssh_generic_check PermitEmptyPasswords no
if [ $? -eq 0 ]; then
    echo "OK: SSH PermitEmptyPasswords no"
else    
    ssh_generic_change PermitEmptyPasswords no
fi

echo 
ssh_generic_check ClientAliveInterval 300
if [ $? -eq 0 ]; then
    echo "OK: SSH ClientAliveInterval 300"
else    
    ssh_generic_change ClientAliveInterval 300
fi

echo 
ssh_generic_check ClientAliveCountMax 0
if [ $? -eq 0 ]; then
    echo "OK: SSH ClientAliveCountMax 0"
else    
    ssh_generic_change ClientAliveCountMax 0
fi

echo 
ssh_generic_check PermitRootLogin no
if [ $? -eq 0 ]; then
    echo "OK: SSH PermitRootLogin no"
else    
    ssh_generic_change PermitRootLogin no
fi

echo
echo "OK: AllowGroups  oper batch ansible administrator"
replace_or_append '/etc/ssh/sshd_config' '^AllowGroups' 'oper batch ansible administrator' '#### hardening SSHD ###' '%s %s'


echo 
ssh_generic_check ciphers 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr, aes128-ctr,chacha20-poly1305@openssh.com'
if [ $? -eq 0 ]; then
    echo "OK: SSH ciphers 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com'"
else    
    ssh_generic_change ciphers 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com'
fi

echo 
ssh_generic_check MACs 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com'
if [ $? -eq 0 ]; then
    echo "OK: SSH MACs 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com'"
else    
	ssh_generic_change MACs 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com'
fi

# NON APPLICABILI hmac-ripemd160-etm@openssh.com , hmac-ripemd160

############################################################
### 2.5	 ADVANCED INTRUSION DETECTION ENVIROMENT (AIDE)  ###
### System must be registered to Satellite/rhn or rhel iso repository must be configured ###
############################################################
###
echo
echo "################################################################"
echo "### ** 2.5 ADVANCED INTRUSION DETECTION ENVIROMENT (AIDE) ** ###"
echo "################################################################"
echo 
echo "##### installing aide ..."
yum install -y aide
echo 
echo "##### init  aide DB..."
aide --init

############################################################
################ 2.6	OS SERVICES  ###################
############################################################
echo
echo "###############################################"
echo "########## ** 2.6 **	OS SERVICES #########"
echo "###############################################"
echo 
echo "##### Remove OS Services #####"
yum erase -y cockpit  tftp  tftp-server gssproxy iprutils pigz dhcp openldap-servers openldap-clients bind  httpd samba squid net-snmp
echo

############################################################
################ 2.7 SPECIAL PURPOSE SERVICES  #############
############################################################
echo
echo "###############################################"
echo "#### ** 2.7 ** SPECIAL PURPOSE SERVICES ####"
echo "###############################################"
echo 
echo "##### Tool for managing crypto policies set DEFAULT profile"
update-crypto-policies --set DEFAULT
update-crypto-policies --show
echo
echo "##### Disable AES-128-CBC and AES-256-CBC with crypto policies"
echo 'ssh_cipher = -AES-128-CBC -AES-256-CBC' > /etc/crypto-policies/policies/modules/SSH-NO-CBC.pmod
update-crypto-policies --set DEFAULT:SSH-NO-CBC
update-crypto-policies --show
echo
echo "##### Set default target to multiuser"
systemctl set-default multi-user.target
echo

echo
echo "##################################################"
echo "##### 2.8	NETWORK CONFIGURATION AND FIREWALLS ####"
echo "##################################################"
echo
echo "##### Setting values in /etc/sysctl.conf #####"
replace_or_append '/etc/sysctl.conf' '^net.ipv4.ip_forward' "0" 'Hardening Rhel8 Lottomatica'
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.send_redirects' "0" 'Hardening Rhel8 Lottomatica'
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.send_redirects' "0" 'Hardening Rhel8 Lottomatica'
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.rp_filter' "1" 'Hardening Rhel8 Lottomatica'
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.rp_filter' "1" 'Hardening Rhel8 Lottomatica'
replace_or_append '/etc/sysctl.conf' '^net.ipv4.tcp_syncookies' "1" 'Hardening Rhel8 Lottomatica'
echo

############################################################
################ ** 2.9 ** DISABLE IPV6 **  ################
############################################################

echo "###############################################"
echo "########## ** 2.9 ** DISABLE IPV6 #############"
echo "###############################################"
echo 
echo "##### Disable IPv6 #####"
replace_or_append '/etc/sysctl.conf' '^net.ipv6.conf.all.disable_ipv6' "1" 'Hardening Rhel8 Lottomatica'

echo 
echo "### Applying  sysctl.conf ####"
sysctl -p /etc/sysctl.conf




echo "###############################################"
echo "##### ** 2.10 ** SYSTEM MAINTENANCE  ##########"
echo "###############################################"
echo 
echo "### Disable Ctrl-Alt-Del actions ###"
replace_or_append '/etc/systemd/system.conf' '^CtrlAltDelBurstAction=' 'none' 'CCE-80784-2' '%s=%s'
systemctl mask ctrl-alt-del.target
echo
echo "### Set Permissions on system files: ###"
echo "Set Permissions on /etc/passwd"
 /bin/chmod 644 /etc/passwd
echo "Set Permissions on /etc/shadow"
 /bin/chmod 000 /etc/shadow
echo "Set Permissions on /etc/gshadow"
 /bin/chmod 000 /etc/gshadow
echo "Set Permissions on /etc/group"
 /bin/chmod 644 /etc/group
echo "Set User/Group Ownership on /etc/passwd"
 /bin/chown root:root /etc/passwd
echo "Set User/Group Ownership on /etc/shadow"
 /bin/chown root:root /etc/shadow
echo "Set User/Group Ownership on /etc/gshadow"
 /bin/chown root:root /etc/gshadow
echo "Set User/Group Ownership on /etc/group"
 /bin/chown root:root /etc/group

echo
echo "### Limit the Number of Concurrent Login Sessions Allowed Per User ###"
var_accounts_max_concurrent_login_sessions="10"

if grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.d/*.conf; then
    sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.d/*.conf
elif grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.conf; then
    sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.conf
else
    echo "* hard maxlogins $var_accounts_max_concurrent_login_sessions" >> /etc/security/limits.conf
fi

