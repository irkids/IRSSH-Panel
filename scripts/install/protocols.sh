#!/bin/bash

# Install all VPN protocols
install_protocols() {
    log "Installing VPN protocols..."
    mkdir -p "$PROTOCOLS_DIR"

    [ "$INSTALL_SSH" = true ] && install_ssh
    [ "$INSTALL_L2TP" = true ] && install_l2tp
    [ "$INSTALL_IKEV2" = true ] && install_ikev2
    [ "$INSTALL_CISCO" = true ] && install_cisco
    [ "$INSTALL_WIREGUARD" = true ] && install_wireguard
    [ "$INSTALL_SINGBOX" = true ] && install_singbox
}

# Install SSH Server
install_ssh() {
    log "Installing SSH server..."
    
    # Install OpenSSH
    apt-get install -y openssh-server || error "Failed to install OpenSSH"
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << EOL
Port $SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOL

    # Install Dropbear
    apt-get install -y dropbear || error "Failed to install Dropbear"
    
    # Configure Dropbear
    cat > /etc/default/dropbear << EOL
NO_START=0
DROPBEAR_PORT=$DROPBEAR_PORT
DROPBEAR_EXTRA_ARGS="-w"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOL

    # Setup Banner
    echo "Welcome to IRSSH Panel" > /etc/issue.net

    # Restart services
    systemctl restart ssh dropbear
}

# Install L2TP/IPsec
install_l2tp() {
    log "Installing L2TP/IPsec..."
    
    apt-get install -y strongswan xl2tpd || error "Failed to install L2TP packages"
    
    # Configure strongSwan
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    keyexchange=ikev1
    authby=secret
    ike=aes128-sha1-modp1024,aes128-sha1-modp1536
    esp=aes128-sha1,aes256-sha256

conn L2TP-PSK
    keyexchange=ikev1
    left=%defaultroute
    auto=add
    authby=secret
    type=transport
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    pfs=no
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOL

    # Generate IPsec PSK
    IPSEC_PSK=$(openssl rand -base64 32)
    echo ": PSK \"$IPSEC_PSK\"" > /etc/ipsec.secrets
    
    # Configure xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
[global]
port = $L2TP_PORT
auth file = /etc/ppp/chap-secrets
ipsec saref = yes

[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
refuse chap = yes
refuse pap = yes
require authentication = yes
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOL

    # Configure PPP
    cat > /etc/ppp/options.xl2tpd << EOL
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-l2tp-ipsec.conf
    sysctl -p /etc/sysctl.d/60-l2tp-ipsec.conf

    # Restart services
    systemctl restart strongswan xl2tpd
}

# Install IKEv2
install_ikev2() {
    log "Installing IKEv2..."
    
    apt-get install -y strongswan strongswan-pki || error "Failed to install IKEv2 packages"
    
    # Generate certificates
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca.key.pem
    chmod 600 /etc/ipsec.d/private/ca.key.pem
    
    ipsec pki --self --ca --lifetime 3650 \
        --in /etc/ipsec.d/private/ca.key.pem \
        --type rsa --dn "CN=IRSSH VPN CA" \
        --outform pem > /etc/ipsec.d/cacerts/ca.cert.pem

    # Generate server certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server.key.pem
    chmod 600 /etc/ipsec.d/private/server.key.pem

    ipsec pki --pub --in /etc/ipsec.d/private/server.key.pem --type rsa | \
        ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca.cert.pem \
            --cakey /etc/ipsec.d/private/ca.key.pem \
            --dn "CN=IRSSH VPN Server" \
            --san "IRSSH VPN Server" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server.cert.pem

    # Configure strongSwan for IKEv2
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@server
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightdns=8.8.8.8,8.8.4.4
    rightsourceip=10.10.10.0/24
    rightsendcert=never
    eap_identity=%identity
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-ikev2.conf
    sysctl -p /etc/sysctl.d/60-ikev2.conf

    # Restart strongSwan
    systemctl restart strongswan
}

# Install Cisco AnyConnect (ocserv)
install_cisco() {
    log "Installing Cisco AnyConnect (ocserv)..."
    
    apt-get install -y ocserv || error "Failed to install ocserv"

    # Generate self-signed certificate
    mkdir -p /etc/ocserv/ssl
    
    # Generate key
    certtool --generate-privkey --outfile /etc/ocserv/ssl/server-key.pem
    
    # Create template
    cat > /etc/ocserv/ssl/server.tmpl << EOL
organization = IRSSH VPN
cn = Server
tls_www_server
signing_key
encryption_key
EOL

    # Generate certificate
    certtool --generate-self-signed \
        --load-privkey /etc/ocserv/ssl/server-key.pem \
        --template /etc/ocserv/ssl/server.tmpl \
        --outfile /etc/ocserv/ssl/server-cert.pem

    # Configure ocserv
    cat > /etc/ocserv/ocserv.conf << EOL
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $CISCO_PORT
udp-port = $CISCO_PORT
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
max-clients = 0
max-same-clients = 0
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-utmp = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 192.168.1.0/24
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
ping-leases = false
route = default
no-route = 192.168.1.0/255.255.255.0
cisco-client-compat = true
dtls-legacy = true
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-ocserv.conf
    sysctl -p /etc/sysctl.d/60-ocserv.conf

    # Restart ocserv
    systemctl restart ocserv
}

# Install WireGuard
install_wireguard() {
    log "Installing WireGuard..."
    
    apt-get install -y wireguard || error "Failed to install WireGuard"

    # Generate keys
    mkdir -p /etc/wireguard
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    
    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = 10.0.0.1/24
ListenPort = $WIREGUARD_PORT
PrivateKey = $(cat /etc/wireguard/server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client configurations will be added here
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-wireguard.conf
    sysctl -p /etc/sysctl.d/60-wireguard.conf

    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
}

# Install SingBox
install_singbox() {
    log "Installing SingBox..."
    
    # Get latest release version
    SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    # Download and install
    wget "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
    tar -xzf "sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
    mv "sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box

    # Create config directory
    mkdir -p /etc/sing-box

    # Create basic configuration
    cat > /etc/sing-box/config.json << EOL
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": $SINGBOX_PORT,
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOL

    # Create systemd service
    cat > /etc/systemd/system/sing-box.service << EOL
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/var/lib/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
}

# Install BadVPN
install_badvpn() {
    log "Installing BadVPN..."
    
    # Install build dependencies
    apt-get install -y cmake build-essential screen || error "Failed to install BadVPN dependencies"

    # Download and compile BadVPN
    cd /usr/local/src
    wget https://github.com/ambrop72/badvpn/archive/refs/heads/master.zip
    unzip master.zip
    cd badvpn-master
    mkdir build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make install

    # Create systemd service
    cat > /etc/systemd/system/badvpn.service << EOL
[Unit]
Description=BadVPN UDPGW Service
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$BADVPN_PORT --max-clients 500
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start service
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
}

# Verify protocol installations
verify_protocols() {
    log "Verifying protocol installations..."

    [ "$INSTALL_SSH" = true ] && ! systemctl is-active --quiet ssh && error "SSH service is not running"
    [ "$INSTALL_L2TP" = true ] && ! systemctl is-active --quiet strongswan && error "L2TP service is not running"
    [ "$INSTALL_IKEV2" = true ] && ! systemctl is-active --quiet strongswan && error "IKEv2 service is not running"
    [ "$INSTALL_CISCO" = true ] && ! systemctl is-active --quiet ocserv && error "Cisco AnyConnect service is not running"
    [ "$INSTALL_WIREGUARD" = true ] && ! systemctl is-active --quiet wg-quick@wg0 && error "WireGuard service is not running"
    [ "$INSTALL_SINGBOX" = true ] && ! systemctl is-active --quiet sing-box && error "SingBox service is not running"
    ! systemctl is-active --quiet badvpn && error "BadVPN service is not running"
}

# Save protocol configurations
save_protocol_configs() {
    log "Saving protocol configurations..."

    mkdir -p "$CONFIG_DIR/protocols"
    
    # Save SSH config
    cp /etc/ssh/sshd_config "$CONFIG_DIR/protocols/ssh_config"
    cp /etc/default/dropbear "$CONFIG_DIR/protocols/dropbear_config"
    
    # Save L2TP/IPsec config
    cp /etc/ipsec.conf "$CONFIG_DIR/protocols/ipsec_config"
    cp /etc/xl2tpd/xl2tpd.conf "$CONFIG_DIR/protocols/xl2tpd_config"
    
    # Save IKEv2 config
    cp -r /etc/ipsec.d "$CONFIG_DIR/protocols/ipsec.d"
    
    # Save Cisco config
    cp -r /etc/ocserv "$CONFIG_DIR/protocols/ocserv"
    
    # Save WireGuard config
    cp -r /etc/wireguard "$CONFIG_DIR/protocols/wireguard"
    
    # Save SingBox config
    cp -r /etc/sing-box "$CONFIG_DIR/protocols/singbox"

    chmod -R 600 "$CONFIG_DIR/protocols"
}
