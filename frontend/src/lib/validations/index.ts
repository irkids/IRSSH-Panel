// src/lib/validations/index.ts
import * as z from 'zod';

export const loginSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

export const userSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(32, 'Username must not exceed 32 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  email: z.string()
    .email('Invalid email address')
    .optional()
    .nullable(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  protocol: z.string(),
  dataLimit: z.number()
    .optional()
    .nullable()
    .transform(val => val === null ? undefined : val),
  validUntil: z.string()
    .optional()
    .nullable(),
  note: z.string()
    .optional()
    .nullable(),
  status: z.enum(['active', 'disabled', 'expired']).default('active')
});

export const protocolConfigSchema = z.object({
  protocol: z.string(),
  port: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  enabled: z.boolean(),
  config: z.record(z.any())
});

export const settingsSchema = z.object({
  serverName: z.string().min(1, 'Server name is required'),
  timezone: z.string().min(1, 'Timezone is required'),
  language: z.string().min(2, 'Language is required'),
  theme: z.enum(['light', 'dark', 'system']).default('system'),
  autoUpdate: z.boolean().default(true),
  email: z.object({
    enabled: z.boolean(),
    smtpServer: z.string().optional(),
    smtpPort: z.number().optional(),
    smtpUser: z.string().optional(),
    smtpPassword: z.string().optional(),
    fromAddress: z.string().email().optional()
  }).optional(),
  telegram: z.object({
    enabled: z.boolean(),
    botToken: z.string().optional(),
    chatId: z.string().optional()
  }).optional()
});

export const backupSchema = z.object({
  components: z.array(
    z.enum(['database', 'config', 'certificates', 'logs'])
  ),
  telegram: z.boolean().default(false),
  cleanup: z.boolean().default(true),
  notes: z.string().optional()
});

export const restoreSchema = z.object({
  backupId: z.number(),
  components: z.array(
    z.enum(['database', 'config', 'certificates'])
  ),
  verify: z.boolean().default(true)
});

export const sshConfigSchema = z.object({
  port: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  maxClients: z.number()
    .min(1, 'Maximum clients must be at least 1'),
  passwordAuth: z.boolean(),
  keyAuth: z.boolean(),
  permitRootLogin: z.boolean(),
  x11Forwarding: z.boolean()
});

export const l2tpConfigSchema = z.object({
  port: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  ipsecPort: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  psk: z.string().min(8, 'PSK must be at least 8 characters'),
  localIpRange: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, 'Invalid IP range format'),
  dnsServers: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}(,(\d{1,3}\.){3}\d{1,3})*$/, 'Invalid DNS servers format')
});

export const ikev2ConfigSchema = z.object({
  port: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  nattPort: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  serverCert: z.string().min(1, 'Server certificate is required'),
  privateKey: z.string().min(1, 'Private key is required'),
  caCert: z.string().min(1, 'CA certificate is required'),
  virtualIpPool: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, 'Invalid IP range format'),
  dnsServers: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}(,(\d{1,3}\.){3}\d{1,3})*$/, 'Invalid DNS servers format')
});

export const wireguardConfigSchema = z.object({
  port: z.number()
    .min(1, 'Port must be greater than 0')
    .max(65535, 'Port must not exceed 65535'),
  serverPrivateKey: z.string().min(1, 'Server private key is required'),
  serverPublicKey: z.string().min(1, 'Server public key is required'),
  serverAddress: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, 'Invalid IP address format'),
  clientAddressPool: z.string().min(1, 'Client address pool is required'),
  dnsServers: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}(,(\d{1,3}\.){3}\d{1,3})*$/, 'Invalid DNS servers format'),
  mtu: z.number().min(1280).max(1500).default(1420)
});

export const singboxConfigSchema = z.object({
  shadowsocks: z.object({
    port: z.number()
      .min(1, 'Port must be greater than 0')
      .max(65535, 'Port must not exceed 65535'),
    method: z.enum([
      'aes-256-gcm',
      'chacha20-poly1305',
      '2022-blake3-aes-256-gcm'
    ]),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    udp: z.boolean()
  }).optional(),
  
  tuic: z.object({
    port: z.number()
      .min(1, 'Port must be greater than 0')
      .max(65535, 'Port must not exceed 65535'),
    uuid: z.string().uuid('Invalid UUID format'),
    congestionControl: z.enum(['bbr', 'cubic', 'new_reno']),
    certificatePath: z.string().min(1, 'Certificate path is required'),
    privateKeyPath: z.string().min(1, 'Private key path is required')
  }).optional(),

  vless: z.object({
    port: z.number()
      .min(1, 'Port must be greater than 0')
      .max(65535, 'Port must not exceed 65535'),
    uuid: z.string().uuid('Invalid UUID format'),
    flow: z.enum(['xtls-rprx-vision', 'xtls-rprx-vision-udp443']),
    tls: z.boolean(),
    serverName: z.string().min(1, 'Server name is required')
  }).optional(),

  hysteria2: z.object({
    port: z.number()
      .min(1, 'Port must be greater than 0')
      .max(65535, 'Port must not exceed 65535'),
    upMbps: z.number().min(1, 'Upload speed must be at least 1 Mbps'),
    downMbps: z.number().min(1, 'Download speed must be at least 1 Mbps'),
    obfsPassword: z.string().min(8, 'OBFS password must be at least 8 characters'),
    cipherMethod: z.enum(['aes', 'chacha20', 'sm4'])
  }).optional()
});
