//Format speed
export function formatSpeed(bytesPerSecond: number): string {
  if (bytesPerSecond === 0) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
  const exp = Math.floor(Math.log(bytesPerSecond) / Math.log(1024));
  const speed = bytesPerSecond / Math.pow(1024, exp);
  return `${speed.toFixed(2)} ${units[exp]}`;
}

// Validate CIDR notation
export function isValidCIDR(cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) return false;
  
  const [ip, prefix] = parts;
  if (!isValidIP(ip)) return false;
  
  const prefixNum = parseInt(prefix, 10);
  return prefixNum >= 0 && prefixNum <= 32;
}

// Generate unique ID
export function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// Format percentage
export function formatPercentage(value: number, decimals: number = 1): string {
  return `${value.toFixed(decimals)}%`;
}

// Get protocol color
export function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    ssh: '#3B82F6',
    l2tp: '#10B981',
    ikev2: '#6366F1',
    cisco: '#F59E0B',
    wireguard: '#EC4899',
    shadowsocks: '#8B5CF6',
    tuic: '#14B8A6',
    vless: '#EF4444',
    hysteria2: '#06B6D4'
  };
  return colors[protocol.toLowerCase()] || '#6B7280';
}

// Format error message
export function formatError(error: any): string {
  if (typeof error === 'string') return error;
  if (error.response?.data?.message) return error.response.data.message;
  if (error.message) return error.message;
  return 'An unknown error occurred';
}

// Parse JWT token
export function parseJWT(token: string): any {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch (e) {
    return null;
  }
}

// Check if token is expired
export function isTokenExpired(token: string): boolean {
  const decoded = parseJWT(token);
  if (!decoded) return true;
  return decoded.exp * 1000 < Date.now();
}

// Format log level
export function formatLogLevel(level: string): {
  label: string;
  color: string;
  bgColor: string;
} {
  const levels: Record<string, { label: string; color: string; bgColor: string }> = {
    error: {
      label: 'Error',
      color: 'text-red-700',
      bgColor: 'bg-red-100'
    },
    warn: {
      label: 'Warning',
      color: 'text-yellow-700',
      bgColor: 'bg-yellow-100'
    },
    info: {
      label: 'Info',
      color: 'text-blue-700',
      bgColor: 'bg-blue-100'
    },
    debug: {
      label: 'Debug',
      color: 'text-gray-700',
      bgColor: 'bg-gray-100'
    }
  };
  return levels[level.toLowerCase()] || levels.info;
}

// Validate domain name
export function isValidDomain(domain: string): boolean {
  const regex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return regex.test(domain);
}

// Check if running in development mode
export const isDev = process.env.NODE_ENV === 'development';

// Format file size
export function formatFileSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  if (bytes === 0) return '0 B';
  const exp = Math.floor(Math.log(bytes) / Math.log(1024));
  const size = (bytes / Math.pow(1024, exp)).toFixed(2);
  return `${size} ${units[exp]}`;
}

// Validate email address
export function isValidEmail(email: string): boolean {
  const regex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  return regex.test(email);
}

// Create range array
export function range(start: number, end: number): number[] {
  return Array.from({ length: end - start + 1 }, (_, i) => start + i);
}

// Group array by key
export function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((groups, item) => {
    const group = String(item[key]);
    groups[group] = groups[group] || [];
    groups[group].push(item);
    return groups;
  }, {} as Record<string, T[]>);
}

// Calculate checksum
export async function calculateChecksum(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Sleep function
export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Check if string is JSON
export function isJSON(str: string): boolean {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
}

// Get browser info
export function getBrowserInfo() {
  const ua = navigator.userAgent;
  let browserName = "Unknown";
  let browserVersion = "Unknown";
  let os = "Unknown";

  if (ua.includes("Firefox/")) {
    browserName = "Firefox";
    browserVersion = ua.split("Firefox/")[1];
  } else if (ua.includes("Chrome/")) {
    browserName = "Chrome";
    browserVersion = ua.split("Chrome/")[1].split(" ")[0];
  } else if (ua.includes("Safari/")) {
    browserName = "Safari";
    browserVersion = ua.split("Version/")[1].split(" ")[0];
  }

  if (ua.includes("Windows")) {
    os = "Windows";
  } else if (ua.includes("Mac OS")) {
    os = "MacOS";
  } else if (ua.includes("Linux")) {
    os = "Linux";
  }

  return { browserName, browserVersion, os };
}

// Capitalize string
export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
} src/lib/utils.ts
import { ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Merge Tailwind classes safely
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Format bytes to human readable string
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

// Format date
export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Format duration
export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / (24 * 60 * 60));
  const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
  const minutes = Math.floor((seconds % (60 * 60)) / 60);
  const parts = [];
  
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  
  return parts.join(' ') || '0m';
}

// Generate random string
export function generateRandomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    .map(x => chars[x % chars.length])
    .join('');
}

// Validate IP address
export function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

// Validate port number
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}

// Deep clone object
export function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

// Debounce function
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  
  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Throttle function
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// Parse query string
export function parseQueryString(queryString: string): Record<string, string> {
  const params = new URLSearchParams(queryString);
  const result: Record<string, string> = {};
  
  params.forEach((value, key) => {
    result[key] = value;
  });
  
  return result;
}

// Create query string
export function createQueryString(params: Record<string, string | number | boolean>): string {
  return Object.entries(params)
    .filter(([_, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

// Color manipulation
export function adjustColor(color: string, amount: number): string {
  const clamp = (num: number) => Math.min(255, Math.max(0, num));
  
  if (color.startsWith('#')) {
    const num = parseInt(color.slice(1), 16);
    const r = clamp(((num >> 16) & 0xFF) + amount);
    const g = clamp(((num >> 8) & 0xFF) + amount);
    const b = clamp((num & 0xFF) + amount);
    
    return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, '0')}`;
  }
  
  return color;
}

// Copy to clipboard
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Failed to copy:', error);
    return false;
  }
}

//
