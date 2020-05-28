#!/bin/bash
echo "##### Il server deve avere hostname già configurato ####"
echo "Se la macchina è in produzione occorre valorizzare la variabile Qradar"
echo "Inserisci l'ip del qradar o Premi Invio per continuare senza:"
read QRADAR 

echo "############# DISABLING FIREWALLD ##############"
systemctl stop firewalld
systemctl disable firewalld

echo "############# DISABLING SELINUX (reboot required) ################"
sed -i '/^SELINUX=disabled/d' /etc/selinux/config
sed -i 's/^SELINUX=/#SELINUX=/g' /etc/selinux/config
sed -i '/^#SELINUX=/a SELINUX=disabled' /etc/selinux/config

echo "########################### creazione utenza administrator con password standard:"
if id administrator ; then
    echo "Utente Administrator già esistente"
else
    useradd administrator
fi 

echo 'C4mb14m1!' | passwd administrator --stdin
echo "######################### Inserimento utente administrator nei sudoers ###############"
sed -i '/^administrator.*ALL=(ALL).*ALL/d' /etc/sudoers
sed -i '/root\tALL=(ALL)/a administrator    ALL=(ALL)       ALL' /etc/sudoers

echo "#########################Banner SSh###############"
cat > /etc/ssh/sshd-banner << EOF
##################################################
#### working on Server $(hostname) ####################
##################################################
EOF
sed -i '/^Banner/d' /etc/ssh/sshd_config
echo "Banner /etc/ssh/sshd-banner" >> /etc/ssh/sshd_config
systemctl restart sshd

echo "########################### FILE HOSTS ########################"

echo "127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4" > /etc/hosts
echo "################# THIS MACHINE" >> /etc/hosts
nmcli connection show --active | grep -v NAME | while read line ; do
  DEVICE=$(echo  $line | awk '{print $NF}')
  FUNC=$(echo $line | awk '{print $1}' | cut -d '-' -f2)
  IP=$(ip -4 addr show $DEVICE | grep inet | awk '{print $2}' | cut -d '/' -f1)
  if [ $FUNC == "SERVICE" ] ; then
    echo $IP  $(hostname) >> /etc/hosts
  else
    echo $IP  $(hostname)-$FUNC >> /etc/hosts
  fi
done
cat /etc/hosts
echo
echo
echo "######################### RESOLV.CONF ########################"
cat > /etc/resolv.conf << EOF
domain lottomatica.net
nameserver 172.26.5.110
nameserver 172.26.5.111
EOF
cat /etc/resolv.conf
echo
echo "######################### IMPOSTO QRADAR ########################"
if [ $QRADAR ] ; then
    if ipcalc -c $QRADAR 2>/dev/null ; then 
        echo "OK Qradar: $QRADAR"
        sed -i "/auth.notice;auth.info/d" /etc/rsyslog.conf
        sed -i "/authpriv.* @/d" /etc/rsyslog.conf
        sed -i "/local0.info @/d" /etc/rsyslog.conf
        echo -e "auth.notice;auth.info @$QRADAR\nauthpriv.* @$QRADAR\nlocal0.info @$QRADAR" >> /etc/rsyslog.conf
        systemctl restart rsyslog
    else
        echo "KO: Qradar inserito non valido"
    fi
    
fi

echo "############## Monto la iso del dvd come repository (Mappare virtual media prima)"
if [ -b `lsscsi|egrep "cd/dvd" | awk '{print $7}'` ] ; then 
    mount -t iso9660 `lsscsi|egrep "cd/dvd" | awk '{print $7}'` /mnt 
else 
    echo "ko problemi nel montare la iso di rhel" 
fi

if ! ls /etc/yum.repos.d/media.repo ; then
    cp /mnt/media.repo /etc/yum.repos.d/
    echo "baseurl=file:///mnt" >> /etc/yum.repos.d/media.repo
    echo "enabled=1" >> /etc/yum.repos.d/media.repo
fi

yum repolist

echo "##### Installo software utili #####"
yum install tcpdump bash-completion net-tools  bind-utils iotop chrony telnet -y



echo "############## configuro Chrony ############"
if ls /etc/chrony.conf ; then
    sed -i 's/^server/#server/g' /etc/chrony.conf
    echo "server 10.5.32.25" >> /etc/chrony.conf
    echo "server 10.5.32.26" >> /etc/chrony.conf
    systemctl restart chronyd
    echo "######### Verifica flussi verso gli ntp server:"
    if chronyc tracking | grep 'Not synchronised' ; then
        echo 'KO: Problemi connettività server NTP'
    else
        echo 'OK : Server NTP'
    fi
else
    echo "KO: Chrony NON presente!"
fi

echo 
echo 
echo "###################################################"
echo "### REBOOT NECESSARIO PER DISABILITARE SELINUX ####"
echo "###################################################"


