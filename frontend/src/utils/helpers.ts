// src/utils/helpers.ts

import { format } from 'date-fns';

// Format bytes to human readable format
export const formatBytes = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
};

// Format bandwidth speed
export const formatSpeed = (bytesPerSecond: number): string => {
  return `${formatBytes(bytesPerSecond)}/s`;
};

// Format duration in seconds to human readable format
export const formatDuration = (seconds: number): string => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  return [
    hours > 0 ? `${hours}h` : null,
    minutes > 0 ? `${minutes}m` : null,
    `${secs}s`
  ].filter(Boolean).join(' ');
};

// Format date with custom format
export const formatDate = (date: string | Date, formatStr: string = 'PPpp'): string => {
  return format(new Date(date), formatStr);
};

// Generate random port number
export const generateRandomPort = (min: number = 10000, max: number = 65535): number => {
  return Math.floor(Math.random() * (max - min + 1) + min);
};

// Validate IP address
export const isValidIP = (ip: string): boolean => {
  const regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return regex.test(ip);
};

// Validate port number
export const isValidPort = (port: number): boolean => {
  return port >= 1 && port <= 65535;
};

// Parse connection string
export const parseConnectionString = (str: string): Record<string, string> => {
  const params = new URLSearchParams(str);
  const result: Record<string, string> = {};
  for (const [key, value] of params.entries()) {
    result[key] = value;
  }
  return result;
};

// Generate configuration string
export const generateConfigString = (config: Record<string, string>): string => {
  return Object.entries(config)
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
};

// Color constants for protocol status
export const STATUS_COLORS = {
  active: 'bg-green-100 text-green-800',
  inactive: 'bg-red-100 text-red-800',
  pending: 'bg-yellow-100 text-yellow-800',
  disabled: 'bg-gray-100 text-gray-800'
};

// Protocol icons mapping
export const PROTOCOL_ICONS = {
  ssh: 'Terminal',
  l2tp: 'Globe',
  ikev2: 'Shield',
  cisco: 'Globe',
  wireguard: 'Radio',
  singbox: 'Box'
};

// Validation helpers
export const validation = {
  required: 'This field is required',
  email: 'Invalid email address',
  minLength: (min: number) => `Must be at least ${min} characters`,
  maxLength: (max: number) => `Must be less than ${max} characters`,
  pattern: (pattern: RegExp) => (value: string) => pattern.test(value),
  username: /^[a-zA-Z0-9_-]{3,20}$/,
  password: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/
};

// Error handler
export const handleError = (error: any): string => {
  if (error.response) {
    return error.response.data.message || 'Server error occurred';
  }
  if (error.request) {
    return 'Network error occurred';
  }
  return error.message || 'An error occurred';
};

// Parse query parameters
export const parseQueryParams = (query: string): Record<string, string> => {
  const searchParams = new URLSearchParams(query);
  const params: Record<string, string> = {};
  for (const [key, value] of searchParams.entries()) {
    params[key] = value;
  }
  return params;
};

// Generate query string
export const generateQueryString = (params: Record<string, string>): string => {
  return new URLSearchParams(params).toString();
};
