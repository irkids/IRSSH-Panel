// src/types/index.ts

export interface User {
  id: number;
  username: string;
  email?: string;
  status: UserStatus;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  data_limit?: number;
  protocols: UserProtocol[];
}

export type UserStatus = 'active' | 'disabled' | 'expired';

export interface UserProtocol {
  id: number;
  protocol: ProtocolType;
  config: Record<string, any>;
  enabled: boolean;
}

export type ProtocolType = 
  | 'ssh'
  | 'l2tp'
  | 'ikev2'
  | 'cisco'
  | 'wireguard'
  | 'shadowsocks'
  | 'tuic'
  | 'vless'
  | 'hysteria2';

export interface Connection {
  id: number;
  user_id: number;
  protocol: ProtocolType;
  ip_address: string;
  location?: string;
  connected_at: string;
  disconnected_at?: string;
  bytes_sent: number;
  bytes_received: number;
  client_version?: string;
  device_type?: string;
  os?: string;
}

export interface SystemMetrics {
  cpu: {
    percent: number;
    cores: number;
  };
  memory: {
    total: number;
    used: number;
    free: number;
    percent: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    percent: number;
  };
  network: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
  };
}

export interface ProtocolStats {
  enabled: boolean;
  port: number;
  connections: number;
  bandwidth: {
    in: number;
    out: number;
  };
  uptime: number;
}

export interface BackupInfo {
  id: number;
  filename: string;
  size: number;
  checksum: string;
  components: string[];
  created_at: string;
  status: 'creating' | 'completed' | 'failed';
  notes?: string;
}

export interface AlertConfig {
  thresholds: {
    cpu: number;
    memory: number;
    disk: number;
    bandwidth: number;
  };
  notifications: {
    email: boolean;
    telegram: boolean;
  };
  check_interval: number;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

// Form Types
export interface LoginFormData {
  username: string;
  password: string;
}

export interface UserFormData {
  username: string;
  password?: string;
  email?: string;
  data_limit?: number;
  expires_at?: string;
  protocols: {
    type: ProtocolType;
    config: Record<string, any>;
  }[];
}

export interface ProtocolConfigFormData {
  port: number;
  config: Record<string, any>;
  enabled: boolean;
}

// Theme Type
export type Theme = 'light' | 'dark' | 'system';
