const protocolConfigs = {
  SSH: {
    defaultPort: 22,
    maxConnections: 1000,
    timeout: 3600,
    encryption: ['aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
    authentication: ['password', 'publickey'],
    features: {
      compression: true,
      forwardingEnabled: true,
      x11Forwarding: false
    }
  },
  L2TP: {
    defaultPort: 1701,
    maxConnections: 500,
    timeout: 7200,
    encryption: ['aes256-cbc'],
    authentication: ['chap', 'pap'],
    features: {
      compression: true,
      multilink: true
    }
  },
  IKEv2: {
    defaultPort: 500,
    maxConnections: 500,
    timeout: 7200,
    encryption: ['aes256-gcm-16', 'aes128-gcm-16'],
    authentication: ['certificate', 'eap-mschapv2'],
    features: {
      perfectForwardSecrecy: true,
      mobilitySupport: true
    }
  },
  WIREGUARD: {
    defaultPort: 51820,
    maxConnections: 1000,
    timeout: 0,
    encryption: ['chacha20poly1305'],
    features: {
      persistentKeepalive: true,
      allowedIPs: true
    }
  }
};

module.exports = protocolConfigs;
