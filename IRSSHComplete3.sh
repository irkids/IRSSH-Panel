#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.4.4

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
PROTOCOLS_DIR="$MODULES_DIR/protocols"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Generate secure keys and passwords
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

log "Installing VPN Server module..."
apt-get install -y net-tools iptables

# Installation modes
INSTALL_SSH=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_WIREGUARD=true
INSTALL_SINGBOX=true

# Protocol ports (default values)
SSH_PORT=22
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
WIREGUARD_PORT=51820
SINGBOX_PORT=1080
BADVPN_PORT=7300
DROPBEAR_PORT=22722

cleanup() {
    log "Cleaning up temporary files..."
    rm -rf /tmp/sing-box-*
    rm -rf /tmp/system_stats.json
}

# Logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec &> >(tee -a "$LOG_FILE")
    chmod 640 "$LOG_FILE"
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Initial Setup
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules/protocols}
    mkdir -p "$FRONTEND_DIR"/{public,src/{components,styles,config,utils,assets,layouts}}
    mkdir -p "$BACKEND_DIR"/{app/{api,core,models,schemas,utils},migrations}
    chmod -R 755 "$PANEL_DIR"
}

# Install Dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban \
        sysstat iftop vnstat \
        strongswan xl2tpd ppp \
        ocserv \
        wireguard-tools \
        golang \
        iptables-persistent

    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

    npm install -g npm@8.19.4 || error "npm installation failed"
}

# Install Protocols
install_protocols() {
    log "Installing protocols..."
    mkdir -p "$PROTOCOLS_DIR"

    # Install SSH
    if [ "$INSTALL_SSH" = true ]; then
        log "Installing SSH server..."
        apt-get install -y openssh-server
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
        systemctl restart ssh
    fi

    # Install L2TP
    if [ "$INSTALL_L2TP" = true ]; then
        log "Installing L2TP/IPsec..."
        apt-get install -y strongswan xl2tpd
        
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
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOL
        
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
name = L2TPServer
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOL

        systemctl restart strongswan xl2tpd
    fi

    # Install IKEv2
    if [ "$INSTALL_IKEV2" = true ]; then
        log "Installing IKEv2..."
        apt-get install -y strongswan strongswan-pki
        
        # Generate certificates
        mkdir -p /etc/ipsec.d/{cacerts,certs,private}
        ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca.key.pem
        chmod 600 /etc/ipsec.d/private/ca.key.pem
        
        ipsec pki --self --ca --lifetime 3650 \
            --in /etc/ipsec.d/private/ca.key.pem \
            --type rsa --dn "CN=IRSSH VPN CA" \
            --outform pem > /etc/ipsec.d/cacerts/ca.cert.pem
        
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
    leftcert=server-cert.pem
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
        
       systemctl restart strongswan-starter
    fi

    # Install Cisco AnyConnect
    if [ "$INSTALL_CISCO" = true ]; then
        log "Installing Cisco AnyConnect (ocserv)..."
        apt-get install -y ocserv

        # Generate self-signed certificate
        mkdir -p /etc/ocserv/ssl
        certtool --generate-privkey --outfile /etc/ocserv/ssl/server-key.pem
        cat > /etc/ocserv/ssl/server.tmpl << EOL
organization = IRSSH VPN
cn = Server
tls_www_server
signing_key
encryption_key
EOL
        
        certtool --generate-self-signed \
            --load-privkey /etc/ocserv/ssl/server-key.pem \
            --template /etc/ocserv/ssl/server.tmpl \
            --outfile /etc/ocserv/ssl/server-cert.pem

        # Configure ocserv
        cat > /etc/ocserv/ocserv.conf << EOL
auth = "plain[/etc/ocserv/ocpasswd]"
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

        systemctl restart ocserv
    fi

    # Install WireGuard
    if [ "$INSTALL_WIREGUARD" = true ]; then
        log "Installing WireGuard..."
        apt-get install -y wireguard

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
EOL

        systemctl enable wg-quick@wg0
        systemctl start wg-quick@wg0
    fi

    # Install SingBox
    if [ "$INSTALL_SINGBOX" = true ]; then
        log "Installing SingBox..."
        # Download latest sing-box release
SINGBOX_VERSION="v1.16.0"  # Use a fixed version to avoid errors
wget "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION#v}-linux-amd64.tar.gz" || error "Failed to download SingBox"
tar -xzf sing-box-${SINGBOX_VERSION#v}-linux-amd64.tar.gz || error "Failed to extract SingBox"
mv sing-box-${SINGBOX_VERSION#v}-linux-amd64/sing-box /usr/local/bin/ || error "Failed to move SingBox binary"
chmod +x /usr/local/bin/sing-box || error "Failed to set executable permissions for SingBox"

        # Create basic configuration
        mkdir -p /etc/sing-box
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

        systemctl daemon-reload
        systemctl enable sing-box
        systemctl start sing-box
    fi
}

# Setup Frontend
setup_frontend() {
    log "Setting up frontend..."
    cd "$FRONTEND_DIR"

    # Install dependencies
    log "Installing frontend dependencies..."
    npm install --legacy-peer-deps || error "Failed to install frontend dependencies"

    # Install react-scripts explicitly
    npm install react-scripts@5.0.1 --legacy-peer-deps || error "Failed to install react-scripts"

    # Build the frontend
    log "Building frontend..."
    GENERATE_SOURCEMAP=false npm run build || error "Frontend build failed"
}

    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.4.4",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "recharts": "^2.5.0",
    "clsx": "^1.2.1",
    "react-scripts": "5.0.1",
    "@babel/plugin-proposal-private-property-in-object": "^7.21.11",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "GENERATE_SOURCEMAP=false react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ]
  }
}
EOL

    # Create layouts
    mkdir -p src/layouts
    cat > src/layouts/MainLayout.js << 'EOL'
import React from 'react';
import Sidebar from '../components/Sidebar';

const MainLayout = ({ children }) => {
  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar />
      <div className="flex-1 overflow-auto">
        {children}
      </div>
    </div>
  );
};

export default MainLayout;
EOL

    # Create Sidebar component
    cat > src/components/Sidebar.js << 'EOL'
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { removeToken } from '../utils/auth';
import clsx from 'clsx';

const MenuItem = ({ icon, label, to, children, isActive }) => {
  const [isOpen, setIsOpen] = React.useState(false);

  return (
    <div>
      <Link
        to={to}
        className={clsx(
          'flex items-center px-4 py-2 text-sm rounded-lg mx-2',
          isActive
            ? 'bg-indigo-100 text-indigo-700'
            : 'text-gray-700 hover:bg-gray-100'
        )}
        onClick={() => setIsOpen(!isOpen)}
      >
        {icon}
        <span className="ml-3">{label}</span>
        {children && (
          <svg
            className={`w-4 h-4 ml-auto transform ${isOpen ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        )}
      </Link>
      {children && isOpen && (
        <div className="ml-8 mt-2 space-y-1">{children}</div>
      )}
    </div>
  );
};

const Sidebar = () => {
  const location = useLocation();
  const handleLogout = () => {
    removeToken();
    window.location.href = '/login';
  };

  return (
    <div className="w-64 bg-white shadow-md">
      <div className="h-16 flex items-center px-4">
        <img src="/logo.png" alt="IRSSH" className="h-8 w-8" />
        <span className="ml-2 text-xl font-bold">IRSSH Panel</span>
      </div>
      <div className="px-2 py-4">
        <div className="space-y-1">
          <MenuItem
            to="/dashboard"
            icon={<svg className="w-5 h-5" /* Dashboard icon */ />}
            label="Dashboard"
            isActive={location.pathname === '/dashboard'}
          />
          <MenuItem
            icon={<svg className="w-5 h-5" /* Users icon */ />}
            label="User Management"
          >
            <MenuItem
              to="/users/ssh"
              label="SSH Users"
              isActive={location.pathname === '/users/ssh'}
            />
            <MenuItem
              to="/users/l2tp"
              label="L2TP Users"
              isActive={location.pathname === '/users/l2tp'}
            />
            <MenuItem
              to="/users/ikev2"
              label="IKEv2 Users"
              isActive={location.pathname === '/users/ikev2'}
            />
            <MenuItem
              to="/users/cisco"
              label="Cisco Users"
              isActive={location.pathname === '/users/cisco'}
            />
            <MenuItem
              to="/users/wireguard"
              label="WireGuard Users"
              isActive={location.pathname === '/users/wireguard'}
            />
            <MenuItem
              to="/users/singbox"
              label="SingBox Users"
              isActive={location.pathname === '/users/singbox'}
            />
            <MenuItem
              to="/users/all"
              label="All Users"
              isActive={location.pathname === '/users/all'}
            />
          </MenuItem>
          <MenuItem
            to="/online"
            icon={<svg className="w-5 h-5" /* Online icon */ />}
            label="Online User"
            isActive={location.pathname === '/online'}
          />
          <MenuItem
            to="/settings"
            icon={<svg className="w-5 h-5" /* Settings icon */ />}
            label="Settings"
            isActive={location.pathname === '/settings'}
          />
          <MenuItem
            to="/reports"
            icon={<svg className="w-5 h-5" /* Reports icon */ />}
            label="Reports"
            isActive={location.pathname === '/reports'}
          />
          <button
            onClick={handleLogout}
            className="w-full text-left flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg mx-2"
          >
            <svg className="w-5 h-5" /* Logout icon */ />
            <span className="ml-3">Logout</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
EOL

mkdir -p "$FRONTEND_DIR/src/components/Dashboard"

    # Create Dashboard components
    cat > src/components/Dashboard/ResourceStats.js << 'EOL'
import React from 'react';

const ResourceCircle = ({ value, label, icon }) => (
    <div className="relative w-32 h-32 mx-auto">
        <svg className="w-full h-full transform -rotate-90">
            <circle
                cx="64"
                cy="64"
                r="60"
                fill="none"
                stroke="#e5e7eb"
                strokeWidth="8"
            />
            <circle
                cx="64"
                cy="64"
                r="60"
                fill="none"
                stroke="#10b981"
                strokeWidth="8"
                strokeDasharray={`${value * 3.77} 377`}
                strokeLinecap="round"
            />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center flex-col">
            <span className="text-2xl font-bold">{value}%</span>
            <span className="text-sm text-gray-500">{label}</span>
            {icon}
        </div>
    </div>
);

const ResourceStats = ({ cpuUsage, ramUsage, diskUsage }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Server Resource Statistics</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <ResourceCircle
                    value={cpuUsage}
                    label="CPU Usage"
                    icon={<svg className="w-6 h-6 mt-2" /* CPU icon */ />}
                />
                <ResourceCircle
                    value={ramUsage}
                    label="RAM Usage"
                    icon={<svg className="w-6 h-6 mt-2" /* RAM icon */ />}
                />
                <ResourceCircle
                    value={diskUsage}
                    label="Disk Usage"
                    icon={<svg className="w-6 h-6 mt-2" /* Disk icon */ />}
                />
            </div>
        </div>
    );
};

export default ResourceStats;
EOL

    cat > src/components/Dashboard/BandwidthStats.js << 'EOL'
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const BandwidthStats = ({ monthlyData, dailyData }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Bandwidth Statistics</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                    <h3 className="text-lg font-medium mb-4">Monthly Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={monthlyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" name="Send" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" name="Receive" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" name="Total" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div>
                    <h3 className="text-lg font-medium mb-4">Daily Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={dailyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" name="Send" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" name="Receive" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" name="Total" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default BandwidthStats;
EOL

    cat > src/components/Dashboard/ProtocolStats.js << 'EOL'
import React from 'react';

const ProtocolStats = ({ protocols }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Protocol Statistics</h2>
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead>
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Online Users</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol port</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incoming Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Outgoing Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time Of Being Online</th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {protocols.map((protocol, index) => (
                            <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.name}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.onlineUsers}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.port}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.incomingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.outgoingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.timeOnline}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ProtocolStats;
EOL

    cat > src/components/Dashboard/UserStats.js << 'EOL'
import React from 'react';

const StatBox = ({ label, value, color }) => (
    <div className="text-center">
        <div className={`text-${color}-600 font-medium`}>{label}</div>
        <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
);

const UserStats = ({ stats }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Users Statistics</h2>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <StatBox label="Active" value={stats.active} color="green" />
                <StatBox label="Expired" value={stats.expired} color="red" />
                <StatBox label="Expired in 24h" value={stats.expiredSoon} color="yellow" />
                <StatBox label="Deactive" value={stats.deactive} color="gray" />
                <StatBox label="Online" value={stats.online} color="blue" />
            </div>
        </div>
    );
};

export default UserStats;
EOL

    # Create Dashboard index
    cat > src/components/Dashboard/index.js << 'EOL'
import React, { useState, useEffect } from 'react';
import axios from '../../config/axios';
import ResourceStats from './ResourceStats';
import BandwidthStats from './BandwidthStats';
import ProtocolStats from './ProtocolStats';
import UserStats from './UserStats';
import MainLayout from '../../layouts/MainLayout';

const Dashboard = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [data, setData] = useState({
        resources: { cpu: 0, ram: 0, disk: 0 },
        bandwidth: {
            monthly: [],
            daily: []
        },
        protocols: [],
        users: {
            active: 0,
            expired: 0,
            expiredSoon: 0,
            deactive: 0,
            online: 0
        }
    });

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('/api/monitoring/system');
                setData(response.data);
                setError(null);
            } catch (err) {
                console.error('Error fetching dashboard data:', err);
                setError('Failed to load dashboard data');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
                </div>
            </MainLayout>
        );
    }

    if (error) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                        {error}
                    </div>
                </div>
            </MainLayout>
        );
    }

    return (
        <MainLayout>
            <div className="p-6 space-y-6">
                <ResourceStats
                    cpuUsage={data.resources.cpu}
                    ramUsage={data.resources.ram}
                    diskUsage={data.resources.disk}
                />
                <BandwidthStats
                    monthlyData={data.bandwidth.monthly}
                    dailyData={data.bandwidth.daily}
                />
                <ProtocolStats protocols={data.protocols} />
                <UserStats stats={data.users} />
            </div>
        </MainLayout>
    );
};

export default Dashboard;
EOL

    # Create App.js
    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard';
import PrivateRoute from './components/Auth/PrivateRoute';

const App = () => {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route
                    path="/dashboard"
                    element={
                        <PrivateRoute>
                            <Dashboard />
                        </PrivateRoute>
                    }
                />
                <Route path="/" element={<Navigate to="/dashboard" />} />
            </Routes>
        </BrowserRouter>
    );
};

export default App;
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);
EOL

    # Create styles
    cat > src/styles/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
        'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
        sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

.resource-circle {
    transition: stroke-dasharray 0.5s ease;
}

.bandwidth-chart {
    width: 100%;
    height: 100%;
    min-height: 300px;
}

.protocol-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
}

.protocol-table th,
.protocol-table td {
    padding: 12px;
    text-align: left;
}

.protocol-table th {
    background-color: #f9fafb;
    font-weight: 600;
}

.protocol-table tr:nth-child(even) {
    background-color: #f9fafb;
}

.user-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    padding: 1rem;
}
EOL

    # Install dependencies and build
    log "Installing frontend dependencies..."
    npm install

    log "Building frontend..."
    GENERATE_SOURCEMAP=false npm run build

    if [ $? -eq 0 ]; then
        log "Frontend built successfully"
    else
        error "Frontend build failed"
    fi
}

setup_python() {
    log "Setting up Python virtual environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install fastapi uvicorn sqlalchemy psycopg2-binary python-multipart
}

# Setup Python Backend
setup_python_backend() {
    log "Setting up Python backend..."
    source "$PANEL_DIR/venv/bin/activate"

    # Create monitoring module for real system stats
    cat > "$BACKEND_DIR/app/utils/monitoring.py" << 'EOL'
import psutil
import time
from datetime import datetime
import os

class SystemMonitor:
    def __init__(self):
        self.start_time = time.time()
        self._network_last = psutil.net_io_counters()
        self._last_check = time.time()

    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=1)

    def get_memory_usage(self):
        memory = psutil.virtual_memory()
        return memory.percent

    def get_disk_usage(self):
        disk = psutil.disk_usage('/')
        return disk.percent

    def get_network_usage(self):
        current = psutil.net_io_counters()
        current_time = time.time()
        time_diff = current_time - self._last_check

        send_speed = (current.bytes_sent - self._network_last.bytes_sent) / time_diff
        recv_speed = (current.bytes_recv - self._network_last.bytes_recv) / time_diff

        self._network_last = current
        self._last_check = current_time

        return {
            'send': f"{send_speed / 1024 / 1024:.1f}",
            'receive': f"{recv_speed / 1024 / 1024:.1f}"
        }

    def get_protocol_stats(self):
        return [
            {
                'name': protocol,
                'port': port,
                'onlineUsers': self._get_protocol_users(protocol),
                'traffic': self._get_protocol_traffic(protocol)
            }
            for protocol, port in [
                ('SSH', 22),
                ('L2TP', 1701),
                ('IKEv2', 500),
                ('Cisco', 443),
                ('WireGuard', 51820),
                ('SingBox', 1080)
            ]
        ]

    def _get_protocol_users(self, protocol):
        # Implementation for getting actual protocol users
        return 0

    def _get_protocol_traffic(self, protocol):
        # Implementation for getting actual protocol traffic
        return {'incoming': '0 Mbps', 'outgoing': '0 Mbps'}

    def get_all_stats(self):
        network = self.get_network_usage()
        return {
            'resources': {
                'cpu': self.get_cpu_usage(),
                'ram': self.get_memory_usage(),
                'disk': self.get_disk_usage()
            },
            'bandwidth': {
                'current': network,
                'monthly': [],  # Implement historical data
                'daily': []     # Implement historical data
            },
            'protocols': self.get_protocol_stats(),
            'users': {
                'active': 0,
                'expired': 0,
                'expiredSoon': 0,
                'deactive': 0,
                'online': 0
            }
        }

system_monitor = SystemMonitor()
EOL

    # Create monitoring endpoint
    cat > "$BACKEND_DIR/app/api/monitoring.py" << 'EOL'
from fastapi import APIRouter, Depends
from ..utils.monitoring import system_monitor

router = APIRouter()

@router.get("/system")
async def get_system_info():
    return system_monitor.get_all_stats()
EOL
}

# Setup Database
setup_database() {
    log "Setting up database..."
    systemctl start postgresql
    systemctl enable postgresql

    # Wait for PostgreSQL
    for i in {1..30}; do
        if pg_isready -q; then
            break
        fi
        sleep 1
    done

    # Create database and user
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

    # Save configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${FRONTEND_DIR}/build;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    nginx -t || error "Nginx configuration test failed"
}

# Setup SSL
setup_ssl() {
    if [[ -n "$DOMAIN" ]]; then
        log "Setting up SSL..."
        
        systemctl stop nginx

        # Request certificate
        certbot certonly --standalone \
            -d "$DOMAIN" \
            --non-interactive \
            --agree-tos \
            --email "admin@$DOMAIN" \
            --http-01-port=80 || error "SSL certificate request failed"

        # Update Nginx configuration for SSL
        cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    root ${FRONTEND_DIR}/build;
    index index.html;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
EOL

        systemctl start nginx
    fi
}

# Configure Firewall
setup_firewall() {
    log "Configuring firewall..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow essential services
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow "$WEB_PORT"
    ufw allow "$SSH_PORT"
    ufw allow "$DROPBEAR_PORT"
    ufw allow "$BADVPN_PORT/udp"

    # Allow protocol ports
    [ "$INSTALL_L2TP" = true ] && ufw allow "$L2TP_PORT"
    [ "$INSTALL_IKEV2" = true ] && ufw allow "$IKEV2_PORT"
    [ "$INSTALL_CISCO" = true ] && ufw allow "$CISCO_PORT"
    [ "$INSTALL_WIREGUARD" = true ] && ufw allow "$WIREGUARD_PORT"
    [ "$INSTALL_SINGBOX" = true ] && ufw allow "$SINGBOX_PORT"

    echo "y" | ufw enable
}

# Setup Security
setup_security() {
    log "Setting up security..."

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOL

    systemctl restart fail2ban

    # Secure SSH configuration
    sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Setup Cron Jobs
setup_cron() {
    log "Setting up cron jobs..."

    # Create system monitoring cron job
    cat > /etc/cron.d/irssh-monitor << EOL
* * * * * root $MODULES_DIR/monitor.sh > /tmp/system_stats.json 2>> $LOG_DIR/monitor.err.log
EOL

    # Create bandwidth monitoring cron job
    cat > /etc/cron.d/irssh-bandwidth << EOL
0 * * * * root $MODULES_DIR/bandwidth.sh >> $LOG_DIR/bandwidth.log 2>&1
EOL

    # Create backup cron job
    cat > /etc/cron.d/irssh-backup << EOL
0 0 * * * root $MODULES_DIR/backup.sh >> $LOG_DIR/backup.log 2>&1
EOL

    chmod 644 /etc/cron.d/irssh-*
}

# Verify Installation
verify_installation() {
    log "Verifying installation..."

    # Check services
    local services=(nginx postgresql supervisor)
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            error "Service $service is not running"
        fi
    done

    # Check web server
    if ! curl -s "http://localhost" > /dev/null; then
        error "Web server is not responding"
    fi

    # Check database
    if ! pg_isready -h localhost -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; then
        error "Database is not accessible"
    fi

    # Check backend API
    if ! curl -s "http://localhost:8000/api/health" > /dev/null; then
        error "Backend API is not responding"
    fi

    # Check protocol services
    [ "$INSTALL_L2TP" = true ] && ! systemctl is-active --quiet xl2tpd && error "L2TP service is not running"
    [ "$INSTALL_IKEV2" = true ] && ! systemctl is-active --quiet strongswan && error "IKEv2 service is not running"
    [ "$INSTALL_CISCO" = true ] && ! systemctl is-active --quiet ocserv && error "Cisco AnyConnect service is not running"
    [ "$INSTALL_WIREGUARD" = true ] && ! systemctl is-active --quiet wg-quick@wg0 && error "WireGuard service is not running"
    [ "$INSTALL_SINGBOX" = true ] && ! systemctl is-active --quiet sing-box && error "SingBox service is not running"

    log "All services verified successfully"
}

check_requirements() {
    log "Checking system requirements..."
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root."
    fi

    # Check for required commands
    for cmd in curl wget tar openssl; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Command '$cmd' is required but not installed."
        fi
    done
}

create_backup() {
    log "Creating backup of existing installation..."
    mkdir -p "$BACKUP_DIR"
    if [ -d "$PANEL_DIR" ]; then
        tar -czf "$BACKUP_DIR/irssh-panel-backup-$(date +%Y%m%d%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

# Save Installation Info
save_installation_info() {
    log "Saving installation information..."
    
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.4.4
Domain: ${DOMAIN}
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
Dropbear Port: ${DROPBEAR_PORT}
L2TP Port: ${L2TP_PORT}
IKEv2 Port: ${IKEV2_PORT}
Cisco Port: ${CISCO_PORT}
WireGuard Port: ${WIREGUARD_PORT}
SingBox Port: ${SINGBOX_PORT}
BadVPN Port: ${BADVPN_PORT}
Admin Username: admin
Admin Password: ${ADMIN_PASS}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Database Password: ${DB_PASS}
JWT Secret: ${JWT_SECRET}
EOL
    chmod 600 "$CONFIG_DIR/installation.info"

    # Create environment file for easy access
    cat > "$CONFIG_DIR/env" << EOL
ADMIN_USER="admin"
ADMIN_PASS=$(openssl rand -base64 12)
JWT_SECRET_KEY=${JWT_SECRET}
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
EOL
    chmod 600 "$CONFIG_DIR/env"
}

# Main Installation
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation v3.4.4"
    
    # Automate settings
    DOMAIN=""  # No domain required
    WEB_PORT=443  # Default port
    SSH_PORT=22  # Default SSH port

    # Automatically install all protocols
    INSTALL_SSH=true
    INSTALL_L2TP=true
    INSTALL_IKEV2=true
    INSTALL_CISCO=true
    INSTALL_WIREGUARD=true
    INSTALL_SINGBOX=true

    # Run installation steps
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    install_protocols
    setup_python
    setup_python_backend
    setup_frontend
    setup_database
    setup_nginx
    setup_ssl
    setup_firewall
    setup_security
    setup_cron
    verify_installation
    save_installation_info
    
    log "Installation completed successfully!"
}
    
    # Final output
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Access URLs:"
    if [[ -n "$DOMAIN" ]]; then
        echo "Panel: https://$DOMAIN"
    else
        echo "Panel: http://YOUR-SERVER-IP"
    fi
    echo
    echo "Installed Protocols:"
    [ "$INSTALL_SSH" = true ] && echo "- SSH (Port: $SSH_PORT)"
    [ "$INSTALL_L2TP" = true ] && echo "- L2TP/IPsec (Port: $L2TP_PORT)"
    [ "$INSTALL_IKEV2" = true ] && echo "- IKEv2 (Port: $IKEV2_PORT)"
    [ "$INSTALL_CISCO" = true ] && echo "- Cisco AnyConnect (Port: $CISCO_PORT)"
    [ "$INSTALL_WIREGUARD" = true ] && echo "- WireGuard (Port: $WIREGUARD_PORT)"
    [ "$INSTALL_SINGBOX" = true ] && echo "- SingBox (Port: $SINGBOX_PORT)"
    echo
    echo "Additional Services:"
    echo "- BadVPN: Port $BADVPN_PORT"
    echo "- Dropbear: Port $DROPBEAR_PORT"
    echo
    echo "Installation Log: $LOG_DIR/install.log"
    echo "Installation Info: $CONFIG_DIR/installation.info"
    echo
    echo "Important Notes:"
    echo "1. Please save these credentials securely"
    echo "2. Change the admin password after first login"
    echo "3. Configure additional security settings in the panel"
    echo "4. Check the installation log for any warnings"
    echo "5. A backup of the previous installation (if any) has been saved in: $BACKUP_DIR"
    echo
    echo "For support, please visit the repository issues page."
}

# Start installation
main "$@"
