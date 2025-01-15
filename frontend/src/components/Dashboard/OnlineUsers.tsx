// src/components/Dashboard/OnlineUsers.tsx

import React from 'react';
import { useOnlineUsers } from '@/hooks/api';
import { Shield, Globe, Activity } from 'lucide-react';

const OnlineUsers = () => {
  const { data: users, isLoading } = useOnlineUsers();

  const getProtocolIcon = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'ssh':
        return <Shield className="w-4 h-4 text-blue-500" />;
      case 'l2tp':
      case 'ikev2':
        return <Globe className="w-4 h-4 text-green-500" />;
      default:
        return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  if (isLoading) {
    return (
      <div className="p-4 bg-white rounded-lg shadow">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="p-4 border-b border-gray-200">
        <h3 className="text-lg font-medium text-gray-900">Online Users</h3>
      </div>
      <div className="p-4">
        {users?.length === 0 ? (
          <p className="text-gray-500 text-center">No users currently online</p>
        ) : (
          <div className="space-y-4">
            {users?.map((user) => (
              <div
                key={user.id}
                className="flex items-center justify-between py-2"
              >
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    {getProtocolIcon(user.protocol)}
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-900">
                      {user.username}
                    </p>
                    <p className="text-sm text-gray-500">
                      {user.protocol} • {user.ip_address}
                    </p>
                  </div>
                </div>
                <div className="text-right text-sm text-gray-500">
                  <p>Connected: {formatDuration(user.connected_at)}</p>
                  <p className="text-xs">
                    ↑ {formatBytes(user.bytes_sent)} • ↓{' '}
                    {formatBytes(user.bytes_received)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// Helper functions
const formatDuration = (startTime: string) => {
  const start = new Date(startTime);
  const now = new Date();
  const diff = Math.floor((now.getTime() - start.getTime()) / 1000);

  const hours = Math.floor(diff / 3600);
  const minutes = Math.floor((diff % 3600) / 60);

  return hours > 0
    ? `${hours}h ${minutes}m`
    : `${minutes}m ${diff % 60}s`;
};

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

export default OnlineUsers;
