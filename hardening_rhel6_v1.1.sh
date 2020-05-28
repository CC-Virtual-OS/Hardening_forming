#!/bin/bash

#################################
## Compatible with rh 6.*
## Paolo Fruci & Marco Simonetti
## Documento di riferimento : "Hardening Checklist for Linux RedHat 6_ver 1 6.docx"
#################################


########### FUNCTIONS ###############
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




echo "#### **2.0** Disable Interactive Boot: ** ###"
grep 'PROMPT' /etc/sysconfig/init
echo "#############################################"
echo
echo "#### **2.1** Filesystem Configuration ** ####"
echo "#############################################"
FS='/tmp'
FS_OPT='nodev nosuid noexec'
if mount | grep $FS > /dev/null; then
    echo "OK: $FS created as separated partition"
    for i in $FS_OPT ; do
        if mount | grep $FS | grep $i > /dev/null ; then
            echo "OK: $i option found for $FS Filesystem"
        else
            echo "WARNING: $i option NOT found for $FS Filesystem"
        fi
    done
else
    echo "WARNING: /tmp not configured as separated filesystem"
fi
echo
echo "#############################################"
echo
FS='/dev/shm'
if mount | grep $FS > /dev/null; then
    echo "OK: $FS created as separated partition"
    for i in $FS_OPT ; do
        if mount | grep $FS | grep $i > /dev/null; then
            echo "OK: $i option found for $FS Filesystem"
        else
            echo "WARNING: $i option NOT found for $FS Filesystem"
        fi
    done
else
    echo "WARNING: $FS not configured as separated filesystem"
fi

echo 
echo "###### 2.3	DISABLE SYSTEM ACCOUNTS ####x"
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do 
    if [ $user != "root" ] && [ $user != "administrator" ]
    then
        /usr/sbin/usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ] 
        then
            /usr/sbin/usermod -s /sbin/nologin $user
        fi
    fi 
done

echo 
echo "###### Restrict Core Dumps, kdump abilitato per richiesta di RH #####"
sed -i '/* hard core 0/d' /etc/security/limits.conf
echo '* hard core 0' >> /etc/security/limits.conf

echo
echo "#### **2.3**	CONFIGURE SSH ** ####"

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
ssh_generic_check X11Forwarding no
if [ $? -eq 0 ]; then
    echo "OK: SSH X11Forwarding no"
else    
    ssh_generic_change X11Forwarding no
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
ssh_generic_check PermitUserEnvironment no
if [ $? -eq 0 ]; then
    echo "OK: SSH PermitUserEnvironment no"
else    
    ssh_generic_change PermitUserEnvironment no
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
ssh_generic_check ciphers 'aes128-ctr,aes192-ctr,aes256-ctr'
if [ $? -eq 0 ]; then
    echo "OK: SSH ciphers 'aes128-ctr,aes192-ctr,aes256-ctr'"
else    
    ssh_generic_change ciphers 'aes128-ctr,aes192-ctr,aes256-ctr'
fi

echo 
ssh_generic_check MACs 'hmac-sha2-256,hmac-sha2-512,hmac-sha1'
if [ $? -eq 0 ]; then
    echo "OK: SSH MACs 'hmac-sha2-256,hmac-sha2-512,hmac-sha1'"
else    
    ssh_generic_change MACs 'hmac-sha2-256,hmac-sha2-512,hmac-sha1'
fi


echo 
echo "#### Set Permissions on /etc/ssh/sshd_config ####"
chown root:root /etc/ssh/sshd_config  
chmod 600 /etc/ssh/sshd_config
ls -l /etc/ssh/sshd_config
service sshd restart
echo "##################################"
echo

echo "#### ** 2.8 **	OS SERVICES ####" 
echo "Remove OS Services"
yum erase -y rsh-server rsh ypbind ypserv tftp  tftp-server talk talk-server dhcp openldap-servers openldap-clients bind  httpd samba squid net-snmp
echo "    Disable the chargen-dgram service :"
chkconfig chargen-dgram off
echo "    Disable the charge	n-stream service :"
chkconfig chargen-stream off
echo "    Disable the daytime-dgram service :"
chkconfig daytime-dgram off
echo "    Disable the daytime-stream service :"
chkconfig daytime-stream off
echo "    Disable the echo-dgram service :"
chkconfig echo-dgram off
echo "    Disable the echo-stream service :"
chkconfig echo-stream off
echo "    Disable the tcpmux-server service :"
chkconfig tcpmux-server off
echo "    Disable Avahi Server  :"
chkconfig avahi-daemon off
echo "##################################"
echo

echo "#### 2.9 SPECIAL PURPOSE SERVICES ####"
if ! grep 'id:3:initdefault' /etc/inittab ; then
    sed  -i '/initdefault/ s/^#*/#/' /etc/inittab
    echo "id:3:initdefault:" >> /etc/inittab
else
    echo "OK: init default 3"
fi
echo

echo "#### 2.10	NETWORK CONFIGURATION AND FIREWALLS HARDENING SYSCTL ####"
sed -i '/fs.suid_dumpable/d' /etc/sysctl.conf
sed -i '/kernel.exec-shield/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.send_redirects/d' /etc/sysctl.conf
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
sed -i '/net.ipv4.icmp_ignore_bogus_error_responses/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.rp_filter/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf


    cat >> /etc/sysctl.conf << EOF
fs.suid_dumpable = 0
kernel.exec-shield = 1
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF

sysctl -p /etc/sysctl.conf


echo 
echo "#### 2.11 DISABLE IPV6 ####"
sed -i 's/NETWORKING_IPV6/#NETWORKING_IPV6/g' /etc/sysconfig/network
echo 'NETWORKING_IPV6=no' >> /etc/sysconfig/network
echo 'options ipv6 disable=1'  > /etc/modprobe.d/ipv6.conf 
chkconfig ip6tables off



echo "** 2.9 **	SYSTEM MAINTENANCE"
echo "Set Permissions on system files:"
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