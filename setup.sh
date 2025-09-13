#!/bin/bash -e

echo "--- Adding repositories and installing utilities ---"
echo

export DEBIAN_FRONTEND=noninteractive

# note: software-properties-common is required for add-apt-repository
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository -y universe
add-apt-repository -y restricted
add-apt-repository -y multiverse

apt-get -o Acquire::ForceIPv4=true install -y moreutils dnsutils


echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | grep -oP ' dev \K\S+')
IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)

echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"
echo
echo "** Note: this hostname must already resolve to this machine, to enable Let's Encrypt certificate setup **"
echo "Hostname for internal domain-naming: $HOSTNAME"
echo "Hostname for VPN: sswan.spoons.su"
VPNHOST=swan.spoons.su

VPNHOSTIP=$(dig -4 +short "${VPNHOST}")
[[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname: aborting"

if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
  echo "Warning: $HOSTNAME resolves to ${VPNHOSTIP}, not ${IP}"
  echo "Either you're behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
  read -r -p "Press [Return] to continue anyway, or Ctrl-C to abort"
fi

echo "DNS servers for VPN users: 1.1.1.1,1.0.0.1"
VPNDNS='1.1.1.1,1.0.0.1'


echo
echo "--- Configuration: general server settings ---"
echo

TZONE='Europe/London'

EMAILADDR='admin@spoons.su'

read -r -p "VPN IP pool (default: 10.101.0.0/16): " VPNIPPOOL
VPNIPPOOL=${VPNIPPOOL:-'10.101.0.0/16'}

echo
echo "--- Upgrading and installing packages ---"
echo

apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y

debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get -o Acquire::ForceIPv4=true install -y \
  language-pack-en iptables-persistent postfix mutt unattended-upgrades certbot nginx uuid-runtime \
  strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins

# in 22.04 libcharon-standard-plugins is replaced with libcharon-extauth-plugins
apt-get -o Acquire::ForceIPv4=true install -y libcharon-standard-plugins \
  || apt-get -o Acquire::ForceIPv4=true install -y libcharon-extauth-plugins

echo
echo "--- Configuring firewall ---"
echo

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
#iptables -A INPUT -p udp --dport  500 -j ACCEPT
#iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s "${VPNIPPOOL}" -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d "${VPNIPPOOL}" -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE

iptables -L

netfilter-persistent save

echo
echo "--- Configuring NFS Client ---"
echo

echo "ip.spoons.su:/html /var/www/html nfs defaults,hard,noacl,noexec,nosuid,nolock 0 0" >> /etc/fstab

echo
echo "--- Configuring Web Server ---"
echo

mkdir -p /var/www/html
mount -a
systemctl enable nginx
systemctl start nginx

echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /etc/letsencrypt

# note: currently we stick to RSA because iOS/macOS may have trouble with ECDSA
# (see https://github.com/Spoon-and-Fork/IKEv2-setup/issues/159) 

echo "
authenticator = webroot
webroot-path = /var/www/html
agree-tos = true
non-interactive = true
preferred-challenges = http
rsa-key-size = 4096
email = ${EMAILADDR}
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
" > /etc/letsencrypt/cli.ini

# certbot on older Ubuntu doesn't recognise the --key-type switch, so try without if it errors with
certbot certonly --key-type rsa -d "${VPNHOST}" || certbot certonly -d "${VPNHOST}"

ln -f -s "/etc/letsencrypt/live/${VPNHOST}/cert.pem"    /etc/ipsec.d/certs/cert.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/privkey.pem" /etc/ipsec.d/private/privkey.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/chain.pem"   /etc/ipsec.d/cacerts/chain.pem

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
/etc/letsencrypt/archive/${VPNHOST}/* r,
" >> /etc/apparmor.d/local/usr.lib.ipsec.charon

aa-status --enabled && invoke-rc.d apparmor reload


echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/sysctl.conf || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
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

  # https://docs.strongswan.org/docs/5.9/config/IKEv2CipherSuites.html#_commercial_national_security_algorithm_suite
  # ... but we also allow aes256gcm16-prfsha256-ecp256, because that's sometimes just what macOS proposes
  ike=aes256-sha1-modp1024,aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256!
  esp=aes256-sha1,aes128-sha256-modp3072,aes256gcm16-sha256,aes256gcm16-ecp384!

  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-radius
  eap_identity=%any
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

	
rm /etc/strongswan.conf 
echo "# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files

charon {
	load_modular = yes
	plugins {
		include strongswan.d/charon/*.conf
	eap-radius {

            class_group = yes
            eap_start = no
            load = yes
            accounting = yes
            servers {
                server-a {
                    address = ip.spoons.su
                    auth_port = 1812
                    acct_port = 1813
                    secret = "amsterdam"
                    nas_identifier = "$HOSTNAME"
                    sockets = 5
                }
            }
            dae {
                enable = yes
                listen = 0.0.0.0
                port = 3800
                secret = "amsterdam"
           }
        }
    }
}

include strongswan.d/*.conf" >> /etc/strongswan.conf


echo "${VPNHOST} : RSA \"privkey.pem\"
" > /etc/ipsec.secrets

ipsec restart


echo
echo "--- Timezone, mail, unattended upgrades ---"
echo

timedatectl set-timezone "${TZONE}"
/usr/sbin/update-locale LANG=en_GB.UTF-8


sed -r \
-e "s/^myhostname =.*$/myhostname = $HOSTNAME/" \
-e 's/^inet_interfaces =.*$/inet_interfaces = loopback-only/' \
-i.original /etc/postfix/main.cf

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/aliases || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
root: ${EMAILADDR}
" >> /etc/aliases

newaliases
service postfix restart


sed -r \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart

echo
echo "--- Creating configuration files ---"
echo

cd "/root"

cat << EOF > vpn-ios.mobileconfig
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

cat << EOF > vpn-mac.applescript
set vpnuser to text returned of (display dialog "Please enter your VPN username" default answer "")
set vpnpass to text returned of (display dialog "Please enter your VPN password" default answer "" with hidden answer)
set plist to "<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>AuthName</key>
        <string>" & vpnuser & "</string>
        <key>AuthPassword</key>
        <string>" & vpnpass & "</string>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>"
set tmpdir to do shell script "mktemp -d"
set tmpfile to tmpdir & "/vpn.mobileconfig"
do shell script "touch " & tmpfile
write plist to tmpfile
do shell script "open /System/Library/PreferencePanes/Profiles.prefPane " & tmpfile
delay 5
do shell script "rm " & tmpfile
EOF

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/mime.types || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
application/vnd.strongswan.profile sswan
" >> /etc/mime.types

cat << EOF > vpn-android.sswan
{
  "uuid": "$(uuidgen)",
  "name": "${VPNHOST}",
  "type": "ikev2-eap",
  "remote": {
    "addr": "${VPNHOST}"
  }
}
EOF

cat << EOF > vpn-ubuntu-client.sh
#!/bin/bash -e
if [[ \$(id -u) -ne 0 ]]; then echo "Please run as root (e.g. sudo ./path/to/this/script)"; exit 1; fi

read -p "VPN username (same as entered on server): " VPNUSERNAME
while true; do
read -s -p "VPN password (same as entered on server): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "\$VPNPASSWORD" = "\$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

apt-get install -y strongswan libstrongswan-standard-plugins libcharon-extra-plugins
apt-get install -y libcharon-standard-plugins || true  # 17.04+ only

ln -f -s /etc/ssl/certs/ISRG_Root_X1.pem /etc/ipsec.d/cacerts/

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/ipsec.conf || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
conn ikev2vpn
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        ike=aes256gcm16-prfsha384-ecp384!
        esp=aes256gcm16-ecp384!
        leftsourceip=%config
        leftauth=eap-mschapv2
        eap_identity=VPNUSERNAME_HERE
        right=${VPNHOST}
        rightauth=pubkey
        rightid=@${VPNHOST}
        rightsubnet=0.0.0.0/0
        auto=add  # or auto=start to bring up automatically
" >> /etc/ipsec.conf

grep -Fq 'Spoon-and-Fork/IKEv2-setup' /etc/ipsec.secrets || echo "
# https://github.com/Spoon-and-Fork/IKEv2-setup
\${VPNUSERNAME} : EAP \"\${VPNPASSWORD}\"
" >> /etc/ipsec.secrets

ipsec restart
sleep 5  # is there a better way?

echo "Bringing up VPN ..."
ipsec up ikev2vpn
ipsec statusall

echo
echo -n "Testing IP address ... "
VPNIP=\$(dig -4 +short ${VPNHOST})
ACTUALIP=\$(dig -4 +short myip.opendns.com @resolver1.opendns.com)
if [[ "\$VPNIP" == "\$ACTUALIP" ]]; then echo "PASSED (IP: \${VPNIP})"; else echo "FAILED (IP: \${ACTUALIP}, VPN IP: \${VPNIP})"; fi

echo
echo "To disconnect: ipsec down ikev2vpn"
echo "To reconnect:  ipsec up ikev2vpn"
echo "To connect automatically: change auto=add to auto=start in /etc/ipsec.conf"
EOF

cat << EOF > vpn-instructions.txt
== iOS ==

A configuration profile is attached as vpn-ios.mobileconfig.

Open this attachment. Then go to Settings > General > VPN & Device Management, and find the profile under 'DOWNLOADED PROFILE'.

You will be asked for your device PIN or password, and then your VPN username and password.

These instructions apply to iOS 15. Earlier (and probably later) versions of iOS will also work, but the exact setup steps may differ.


== macOS ==

In macOS Monterey, your VPN username and password must be embedded in the profile file. However, your password cannot be included in a profile sent by email for security reasons.

So: open vpn-mac.applescript and run it from Script Editor. You'll be prompted for your VPN username and password.

System Preferences will then open. Select the profile listed as 'Downloaded' on the left, and click 'Install...' in the main panel.


== Windows ==

You will need Windows 10 Pro or above. Please run the following commands in PowerShell:

\$Response = Invoke-WebRequest -UseBasicParsing -Uri https://valid-isrgrootx1.letsencrypt.org
# ^ this line fixes a certificate lazy-loading bug: see https://github.com/Spoon-and-Fork/IKEv2-setup/issues/126

Add-VpnConnection -Name "${VPNHOST}" \`
  -ServerAddress "${VPNHOST}" \`
  -TunnelType IKEv2 \`
  -EncryptionLevel Maximum \`
  -AuthenticationMethod EAP \`
  -RememberCredential

Set-VpnConnectionIPsecConfiguration -ConnectionName "${VPNHOST}" \`
  -AuthenticationTransformConstants GCMAES256 \`
  -CipherTransformConstants GCMAES256 \`
  -EncryptionMethod GCMAES256 \`
  -IntegrityCheckMethod SHA384 \`
  -DHGroup ECP384 \`
  -PfsGroup ECP384 \`
  -Force

# Run the following command to retain access to the local network (e.g. printers, file servers) while the VPN is connected.
# On a home network, you probably want this. On a public network, you probably don't.

Set-VpnConnection -Name "${VPNHOST}" -SplitTunneling \$True

You will need to enter your chosen VPN username and password in order to connect.


== Android ==

Download the strongSwan app from the Play Store: https://play.google.com/store/apps/details?id=org.strongswan.android

Then open the attached .sswan file, or select it after choosing 'Import VPN profile' from the strongSwan app menu. You will need to enter your chosen VPN username and password in order to connect.

For a persistent connection, go to your device's Settings app and choose Network & Internet > Advanced > VPN > strongSwan VPN Client, tap the gear icon and toggle on 'Always-on VPN' (these options may differ by Android version and provider).


== Ubuntu ==

A bash script to set up strongSwan as a VPN client is attached as vpn-ubuntu-client.sh. You will need to chmod +x and then run the script as root.

EOF

EMAIL=$USER@$HOSTNAME mutt -s "VPN configuration" -a vpn-ios.mobileconfig vpn-mac.applescript vpn-android.sswan vpn-ubuntu-client.sh -- "${EMAILADDR}" < vpn-instructions.txt

echo
echo "--- How to connect ---"
echo
echo "Connection instructions have been emailed to you, and can also be found in your home directory, /root"

# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2


