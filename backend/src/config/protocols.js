const config = {
  ssh: {
    enabled: true,
    port: parseInt(process.env.SSH_PORT || '22'),
    maxConnections: 1000,
    timeout: 3600,
    algorithms: {
      cipher: [
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr'
      ],
      hmac: [
        'hmac-sha2-256-etm@openssh.com',
        'hmac-sha2-512-etm@openssh.com',
        'hmac-sha2-256',
        'hmac-sha2-512'
      ],
      kex: [
        'curve25519-sha256',
        'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521'
      ],
      serverHostKey: [
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'rsa-sha2-512',
        'rsa-sha2-256'
      ]
    }
  },
  l2tp: {
    enabled: true,
    port: parseInt(process.env.L2TP_PORT || '1701'),
    maxConnections: 500,
    timeout: 7200,
    encryption: 'aes256-cbc',
    authentication: ['chap', 'pap']
  },
  ikev2: {
    enabled: true,
    port: parseInt(process.env.IKEV2_PORT || '500'),
    maxConnections: 500,
    timeout: 7200,
    encryption: ['aes256-gcm-16', 'aes128-gcm-16'],
    integrity: ['sha256', 'sha384', 'sha512'],
    dh_groups: ['modp2048', 'modp3072', 'modp4096'],
    certificate: {
      path: process.env.IKEV2_CERT_PATH || '/etc/ipsec.d/certs/server.cert.pem',
      key: process.env.IKEV2_KEY_PATH || '/etc/ipsec.d/private/server.key.pem'
    }
  },
  wireguard: {
    enabled: true,
    port: parseInt(process.env.WIREGUARD_PORT || '51820'),
    maxConnections: 1000,
    interface: 'wg0',
    address: '10.0.0.1/24',
    dns: ['1.1.1.1', '8.8.8.8'],
    mtu: 1420,
    persistentKeepalive: 25
  },
  cisco: {
    enabled: true,
    port: parseInt(process.env.CISCO_PORT || '10443'),
    maxConnections: 500,
    timeout: 3600,
    authentication: ['certificate', 'password'],
    encryption: ['aes256', 'aes128'],
    hash: ['sha256', 'sha1']
  },
  singbox: {
    enabled: true,
    port: parseInt(process.env.SINGBOX_PORT || '443'),
    maxConnections: 1000,
    timeout: 3600,
    methods: [
      'aes-256-gcm',
      'chacha20-poly1305'
    ],
    mux: {
      enabled: true,
      concurrency: 8
    },
    websocket: {
      enabled: true,
      path: '/ws'
    }
  }
};

module.exports = {
  ...config,
  getProtocolConfig: (type) => config[type] || null,
  isProtocolEnabled: (type) => config[type]?.enabled || false,
  getAllEnabledProtocols: () => Object.entries(config)
    .filter(([_, config]) => config.enabled)
    .map(([type]) => type)
};
