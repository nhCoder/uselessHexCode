#!/bin/bash -e

# github.com/jawj/IKEv2-setup
# Copyright (c) 2015 – 2021 George MacKerron
# Released under the MIT licence: http://opensource.org/licenses/mit-license

echo
echo "=== https://github.com/jawj/IKEv2-setup ==="
echo


function exit_badly {
  echo "$1"
  exit 1
}

[[ $(lsb_release -rs) == "18.04" ]] || [[ $(lsb_release -rs) == "20.04" ]] || exit_badly "This script is for Ubuntu 20.04 or 18.04 only: aborting (if you know what you're doing, try deleting this check)"
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"


echo "--- Adding repositories and installing utilities ---"
echo


rm /var/lib/apt/lists/lock
rm /var/cache/apt/archives/lock
rm /var/lib/dpkg/lock*
dpkg --configure -a
apt update


export DEBIAN_FRONTEND=noninteractive

# see https://github.com/jawj/IKEv2-setup/issues/66 and https://bugs.launchpad.net/subiquity/+bug/1783129
# note: software-properties-common is required for add-apt-repository
# apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository universe
add-apt-repository restricted
add-apt-repository multiverse

apt-get -o Acquire::ForceIPv4=true install -y moreutils dnsutils


echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | grep -oP ' dev \K\S+')
# IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)

echo "Network interface: ${ETH0ORSIMILAR}"
# echo "External IP: ${IP}"
# echo
# echo "** Note: this hostname must already resolve to this machine, to enable Let's Encrypt certificate setup **"
read -r -p "Hostname for VPN: " VPNHOST

# VPNHOSTIP=$(dig -4 +short "${VPNHOST}")
# [[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname: aborting"

# if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
#   echo "Warning: ${VPNHOST} resolves to ${VPNHOSTIP}, not ${IP}"
#   echo "Either you're behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
#   read -r -p "Press [Return] to continue anyway, or Ctrl-C to abort"
# fi

read -r -p "VPN username: " VPNUSERNAME

read -r -s -p "VPN password (no quotes, please): " VPNPASSWORD
 echo



echo '
Public DNS servers include:

176.103.130.130,176.103.130.131  AdGuard               https://adguard.com/en/adguard-dns/overview.html
176.103.130.132,176.103.130.134  AdGuard Family        https://adguard.com/en/adguard-dns/overview.html
1.1.1.1,1.0.0.1                  Cloudflare/APNIC      https://1.1.1.1
84.200.69.80,84.200.70.40        DNS.WATCH             https://dns.watch
8.8.8.8,8.8.4.4                  Google                https://developers.google.com/speed/public-dns/
208.67.222.222,208.67.220.220    OpenDNS               https://www.opendns.com
208.67.222.123,208.67.220.123    OpenDNS FamilyShield  https://www.opendns.com
9.9.9.9,149.112.112.112          Quad9                 https://quad9.net
77.88.8.8,77.88.8.1              Yandex                https://dns.yandex.com
77.88.8.88,77.88.8.2             Yandex Safe           https://dns.yandex.com
77.88.8.7,77.88.8.3              Yandex Family         https://dns.yandex.com
'

read -r -p "DNS servers for VPN users (default: 1.1.1.1,1.0.0.1): " VPNDNS
VPNDNS=${VPNDNS:-'1.1.1.1,1.0.0.1'}


echo
echo "--- Configuration: general server settings ---"
echo



# read -r -p "Desired SSH log-in port (default: 22): " SSHPORT

# SSHPORT=${SSHPORT:-22}

# read -r -p "New SSH log-in user name: " LOGINUSERNAME

# CERTLOGIN="n"
# if [[ -s /root/.ssh/authorized_keys ]]; then
#   while true; do
#     read -r -p "Copy /root/.ssh/authorized_keys to new user and disable SSH password log-in [Y/n]? " CERTLOGIN
#     [[ ${CERTLOGIN,,} =~ ^(y(es)?)?$ ]] && CERTLOGIN=y
#     [[ ${CERTLOGIN,,} =~ ^no?$ ]] && CERTLOGIN=n
#     [[ $CERTLOGIN =~ ^(y|n)$ ]] && break
#   done
# fi

# while true; do
#   [[ ${CERTLOGIN} = "y" ]] && read -r -s -p "New SSH user's password (e.g. for sudo): " LOGINPASSWORD
#   [[ ${CERTLOGIN} != "y" ]] && read -r -s -p "New SSH user's log-in password (must be REALLY STRONG): " LOGINPASSWORD
#   echo
#   read -r -s -p "Confirm new SSH user's password: " LOGINPASSWORD2
#   echo
#   [[ "${LOGINPASSWORD}" = "${LOGINPASSWORD2}" ]] && break
#   echo "Passwords didn't match -- please try again"
# done

VPNIPPOOL="10.101.0.0/16"


echo
echo "--- Upgrading and installing packages ---"
echo

# apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y

# debconf-set-selections <<< "postfix postfix/mailname string ${VPNHOST}"
# debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get -o Acquire::ForceIPv4=true install -y language-pack-en strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-standard-plugins libcharon-extra-plugins  iptables-persistent unattended-upgrades uuid-runtime


echo
echo "--- Configuring firewall ---"
echo

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i "${ETH0ORSIMILAR}" -m state --state NEW -m recent --set
iptables -I INPUT -i "${ETH0ORSIMILAR}" -m state --state NEW -m recent --update --seconds 300 --hitcount 60 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT


# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s "${VPNIPPOOL}" -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d "${VPNIPPOOL}" -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE


# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

netfilter-persistent save


echo
echo "--- Configuring RSA certificates ---"
echo

# mkdir -p /etc/letsencrypt

# echo 'rsa-key-size = 4096
# pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
# post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
# renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
# ' > /etc/letsencrypt/cli.ini

# certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email "${EMAILADDR}" -d "${VPNHOST}"

# ln -f -s "/etc/letsencrypt/live/${VPNHOST}/server-cert.pem"    /etc/ipsec.d/certs/server-cert.pem
# ln -f -s "/etc/letsencrypt/live/${VPNHOST}/server-key.pem" /etc/ipsec.d/private/server-key.pem
# ln -f -s "/etc/letsencrypt/live/${VPNHOST}/chain.pem"   /etc/ipsec.d/cacerts/chain.pem

# grep -Fq 'jawj/IKEv2-setup' /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "
# # https://github.com/jawj/IKEv2-setup
# /etc/letsencrypt/archive/${VPNHOST}/* r,
# " >> /etc/apparmor.d/local/usr.lib.ipsec.charon


mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki

cat > gen_certs.sh <<EOF
#!/bin/bash
apt install strongswan-pki -y
ipsec pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem

ipsec pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem \
    --type rsa --dn "CN=VPN root CA" --outform pem > ~/pki/cacerts/ca-cert.pem

ipsec pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem

ipsec pki --pub --in ~/pki/private/server-key.pem --type rsa \
    | ipsec pki --issue --lifetime 1825 \
        --cacert ~/pki/cacerts/ca-cert.pem \
        --cakey ~/pki/private/ca-key.pem \
        --dn "CN=$VPNHOST" --san "$VPNHOST" \
        --flag serverAuth --flag ikeIntermediate --outform pem \
    >  ~/pki/certs/server-cert.pem


cp -r ~/pki/* /etc/ipsec.d/

EOF
chmod +x gen_certs.sh
./gen_certs.sh

# aa-status --enabled && invoke-rc.d apparmor reload

echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'jawj/IKEv2-setup' /etc/sysctl.conf || echo "
# https://github.com/jawj/IKEv2-setup
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.${ETH0ORSIMILAR}.disable_ipv6 = 1
" >> /etc/sysctl.conf

sysctl -p


echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes

  # CNSA/RFC 6379 Suite B (https://wiki.strongswan.org/projects/strongswan/wiki/IKEv2CipherSuites)
  ike=aes256gcm16-prfsha384-ecp384!
  esp=aes256gcm16-ecp384!

  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"server-key.pem\"
${VPNUSERNAME} : EAP \"${VPNPASSWORD}\"
" > /etc/ipsec.secrets

ipsec restart


echo


# echo "--- User ---"
# echo

# # user + SSH

# id -u "${LOGINUSERNAME}" &>/dev/null || adduser --disabled-password --gecos "" "${LOGINUSERNAME}"
# echo "${LOGINUSERNAME}:${LOGINPASSWORD}" | chpasswd
# adduser "${LOGINUSERNAME}" sudo

# sed -r \
# -e "s/^#?Port 22$/Port ${SSHPORT}/" \
# -e 's/^#?LoginGraceTime (120|2m)$/LoginGraceTime 30/' \
# -e 's/^#?PermitRootLogin yes$/PermitRootLogin no/' \
# -e 's/^#?X11Forwarding yes$/X11Forwarding no/' \
# -e 's/^#?UsePAM yes$/UsePAM no/' \
# -i.original /etc/ssh/sshd_config

# grep -Fq 'jawj/IKEv2-setup' /etc/ssh/sshd_config || echo "
# # https://github.com/jawj/IKEv2-setup
# MaxStartups 1
# MaxAuthTries 2
# UseDNS no" >> /etc/ssh/sshd_config

# if [[ $CERTLOGIN = "y" ]]; then
#   mkdir -p "/home/${LOGINUSERNAME}/.ssh"
#   chown "${LOGINUSERNAME}" "/home/${LOGINUSERNAME}/.ssh"
#   chmod 700 "/home/${LOGINUSERNAME}/.ssh"

#   cp "/root/.ssh/authorized_keys" "/home/${LOGINUSERNAME}/.ssh/authorized_keys"
#   chown "${LOGINUSERNAME}" "/home/${LOGINUSERNAME}/.ssh/authorized_keys"
#   chmod 600 "/home/${LOGINUSERNAME}/.ssh/authorized_keys"

#   sed -r \
#   -e "s/^#?PasswordAuthentication yes$/PasswordAuthentication no/" \
#   -i.allows_pwd /etc/ssh/sshd_config
# fi

# service ssh restart

# echo "--- Timezone, mail, unattended upgrades ---"
# echo

# timedatectl set-timezone "${TZONE}"
# /usr/sbin/update-locale LANG=en_GB.UTF-8


# sed -r \
# -e "s/^myhostname =.*$/myhostname = ${VPNHOST}/" \
# -e 's/^inet_interfaces =.*$/inet_interfaces = loopback-only/' \
# -i.original /etc/postfix/main.cf

# grep -Fq 'jawj/IKEv2-setup' /etc/aliases || echo "
# # https://github.com/jawj/IKEv2-setup
# root: ${EMAILADDR}
# ${LOGINUSERNAME}: ${EMAILADDR}
# " >> /etc/aliases

# newaliases
# service postfix restart


# sed -r \
# -e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
# -e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
# -e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
# -e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
# -e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
# -i /etc/apt/apt.conf.d/50unattended-upgrades

# echo 'APT::Periodic::Update-Package-Lists "1";
# APT::Periodic::Download-Upgradeable-Packages "1";
# APT::Periodic::AutocleanInterval "7";
# APT::Periodic::Unattended-Upgrade "1";
# ' > /etc/apt/apt.conf.d/10periodic

# service unattended-upgrades restart

# echo
# echo "--- Creating configuration files ---"
# echo

# cd "/home/${LOGINUSERNAME}"

# info=\$(sudo ipsec status tensorflow-exe)
echo "Setting up Crontab tasks."

cat > logscript.sh <<EOF
#!/bin/bash
info=\$(ipsec status tensorflow-exe)
info=\${info##*\(}
noOfConnections=\${info%% up*}
curl -X POST -d "totalConnections=\$noOfConnections" https://wirefoxvpn.com/app-api/add-load
EOF
chmod +x logscript.sh


echo "Logscript file created."

sudo apt install cron
sudo systemctl enable cron
scriptPath="$(pwd)/logscript.sh"
echo "Adding cron job to log data."
crontab -l | { echo "SHELL=/bin/bash 
PATH=/bin:/sbin:/usr/bin:/usr/sbin
*/1 * * * * /bin/bash $scriptPath"; } | crontab -


echo
echo "--- VPN DETAILS ---"
echo "USERNAME: ${VPNUSERNAME}"
echo "PASSWORD: ${VPNPASSWORD}"
echo "HOST: ${VPNHOST}"
echo "Certificate:"
echo
echo
cat /etc/ipsec.d/cacerts/ca-cert.pem

echo
echo "VPN successfully configured!"
# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2
