// src/components/Dashboard/BandwidthChart.tsx

import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { useNetworkStats } from '@/hooks/api';

interface BandwidthChartProps {
  period?: '1h' | '6h' | '24h' | '7d' | '30d';
}

const BandwidthChart: React.FC<BandwidthChartProps> = ({ period = '24h' }) => {
  const { data, isLoading, error } = useNetworkStats(period);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  if (isLoading) {
    return (
      <div className="h-[300px] flex items-center justify-center bg-white rounded-lg border">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-[300px] flex items-center justify-center bg-white rounded-lg border">
        <div className="text-red-500">Failed to load bandwidth data</div>
      </div>
    );
  }

  return (
    <div className="bg-white p-4 rounded-lg border">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium">Bandwidth Usage</h3>
        <div className="text-sm text-gray-500">
          Total: {formatBytes(data?.total_sent + data?.total_received)}
        </div>
      </div>
      
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data?.data}>
            <defs>
              <linearGradient id="sendColor" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.1}/>
                <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="receiveColor" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10B981" stopOpacity={0.1}/>
                <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
              </linearGradient>
            </defs>
            
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(time) => new Date(time).toLocaleTimeString()}
              stroke="#6B7280"
            />
            
            <YAxis 
              tickFormatter={formatBytes}
              stroke="#6B7280"
            />
            
            <Tooltip 
              labelFormatter={(label) => new Date(label).toLocaleString()}
              formatter={(value: number) => [formatBytes(value), '']}
              contentStyle={{
                backgroundColor: 'white',
                border: '1px solid #E5E7EB',
                borderRadius: '0.375rem'
              }}
            />
            
            <Legend />
            
            <Area
              type="monotone"
              dataKey="bytes_sent"
              name="Upload"
              stroke="#3B82F6"
              fillOpacity={1}
              fill="url(#sendColor)"
            />
            
            <Area
              type="monotone"
              dataKey="bytes_received"
              name="Download"
              stroke="#10B981"
              fillOpacity={1}
              fill="url(#receiveColor)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default BandwidthChart;
