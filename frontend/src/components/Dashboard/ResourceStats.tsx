// src/components/Dashboard/ResourceStats.tsx
import React from 'react';
import { Cpu, Memory, HardDrive } from 'lucide-react';
import { useSystemMetrics } from '@/hooks/api';

const ResourceStats = () => {
  const { data: metrics, isLoading, error } = useSystemMetrics();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>Error loading metrics</div>;
  }

  const resources = [
    {
      name: 'CPU Usage',
      value: metrics?.cpu?.percent || 0,
      icon: Cpu,
      color: 'blue'
    },
    {
      name: 'Memory Usage',
      value: metrics?.memory?.percent || 0,
      icon: Memory,
      color: 'green'
    },
    {
      name: 'Disk Usage',
      value: metrics?.disk?.percent || 0,
      icon: HardDrive,
      color: 'purple'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {resources.map((resource) => {
        const Icon = resource.icon;
        return (
          <div
            key={resource.name}
            className={`bg-white rounded-lg shadow p-6 border-l-4 border-${resource.color}-500`}
          >
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{resource.name}</h3>
                <p className="mt-2 text-3xl font-bold">{resource.value}%</p>
              </div>
              <div className={`p-3 bg-${resource.color}-100 rounded-full`}>
                <Icon className={`w-6 h-6 text-${resource.color}-600`} />
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className={`bg-${resource.color}-600 h-2 rounded-full transition-all duration-500`}
                  style={{ width: `${resource.value}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default ResourceStats;
