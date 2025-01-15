// src/components/Users/ConnectionDetails.tsx

import React from 'react';
import { useQuery } from 'react-query';
import axios from '@/lib/axios';
import { 
  Activity,
  Clock, 
  Download,
  Upload,
  Globe,
  Shield,
  Cpu,
  Zap
} from 'lucide-react';

interface ConnectionDetailsProps {
  userId: string;
  username: string;
  protocol: string;
}

const ConnectionDetails: React.FC<ConnectionDetailsProps> = ({ 
  userId, 
  username,
  protocol 
}) => {
  const { data: details, isLoading } = useQuery(
    ['connection-details', userId],
    async () => {
      const { data } = await axios.get(`/users/${userId}/connection`);
      return data;
    },
    {
      refetchInterval: 5000 // Refresh every 5 seconds
    }
  );

  if (isLoading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-gray-200 rounded w-full mb-4"></div>
        <div className="h-24 bg-gray-200 rounded w-full"></div>
      </div>
    );
  }

  if (!details) {
    return (
      <div className="text-center py-4 text-gray-500">
        No connection details available
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm">
      {/* Connection Status */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className={`w-5 h-5 ${
              details.connected ? 'text-green-500' : 'text-gray-400'
            }`} />
            <span className="font-medium">
              {details.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div className="text-sm text-gray-500">
            {details.connected && (
              <div className="flex items-center">
                <Clock className="w-4 h-4 mr-1" />
                {details.connectionDuration}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Connection Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4">
        {/* Data Transfer */}
        <div className="space-y-1">
          <div className="text-sm text-gray-500">Download</div>
          <div className="flex items-center space-x-1">
            <Download className="w-4 h-4 text-blue-500" />
            <span className="font-medium">{details.bytesReceived}</span>
          </div>
        </div>
        <div className="space-y-1">
          <div className="text-sm text-gray-500">Upload</div>
          <div className="flex items-center space-x-1">
            <Upload className="w-4 h-4 text-green-500" />
            <span className="font-medium">{details.bytesSent}</span>
          </div>
        </div>

        {/* Current Speed */}
        <div className="space-y-1">
          <div className="text-sm text-gray-500">Download Speed</div>
          <div className="flex items-center space-x-1">
            <Zap className="w-4 h-4 text-blue-500" />
            <span className="font-medium">{details.downloadSpeed}/s</span>
          </div>
        </div>
        <div className="space-y-1">
          <div className="text-sm text-gray-500">Upload Speed</div>
          <div className="flex items-center space-x-1">
            <Zap className="w-4 h-4 text-green-500" />
            <span className="font-medium">{details.uploadSpeed}/s</span>
          </div>
        </div>
      </div>

      {/* Connection Info */}
      <div className="p-4 border-t border-gray-200">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-medium text-gray-700">Connection Info</h4>
            <dl className="mt-2 text-sm">
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">IP Address</dt>
                <dd className="font-medium">{details.ipAddress}</dd>
              </div>
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">Location</dt>
                <dd className="font-medium">{details.location || 'Unknown'}</dd>
              </div>
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">Protocol</dt>
                <dd className="font-medium">{protocol}</dd>
              </div>
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">Port</dt>
                <dd className="font-medium">{details.port}</dd>
              </div>
            </dl>
          </div>

          <div>
            <h4 className="text-sm font-medium text-gray-700">Client Info</h4>
            <dl className="mt-2 text-sm">
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">Device</dt>
                <dd className="font-medium">{details.deviceInfo}</dd>
              </div>
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">Client Version</dt>
                <dd className="font-medium">{details.clientVersion}</dd>
              </div>
              <div className="flex justify-between py-1">
                <dt className="text-gray-500">OS</dt>
                <dd className="font-medium">{details.os}</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      {/* Connection History */}
      <div className="p-4 border-t border-gray-200">
        <h4 className="text-sm font-medium text-gray-700 mb-2">Recent Connections</h4>
        <div className="space-y-2">
          {details.history?.map((conn: any, index: number) => (
            <div 
              key={index}
              className="flex items-center justify-between text-sm border-b border-gray-100 pb-2"
            >
              <div className="flex items-center space-x-2">
                <Globe className="w-4 h-4 text-gray-400" />
                <span>{conn.ipAddress}</span>
              </div>
              <div className="text-gray-500">
                {new Date(conn.connectedAt).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ConnectionDetails;
