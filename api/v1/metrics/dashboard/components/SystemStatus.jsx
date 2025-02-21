import React from 'react';
import { Server, Cpu, HardDrive, Activity } from 'lucide-react';
import { Card } from '../../../components/common';

const SystemStatus = ({ metrics }) => {
  const {
    cpu,
    memory,
    disk,
    uptime
  } = metrics;

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor(((seconds % 86400) % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <Card
        title="CPU Usage"
        icon={<Cpu className="w-5 h-5" />}
        value={`${cpu.usage.used}%`}
        subtitle={`${cpu.cores} Cores @ ${cpu.speed} MHz`}
        chart={{
          data: cpu.history,
          color: '#3B82F6'
        }}
      />

      <Card
        title="Memory Usage"
        icon={<Server className="w-5 h-5" />}
        value={`${memory.usedPercentage}%`}
        subtitle={`${(memory.used / 1024 / 1024 / 1024).toFixed(2)} GB / ${(memory.total / 1024 / 1024 / 1024).toFixed(2)} GB`}
        chart={{
          data: memory.history,
          color: '#10B981'
        }}
      />

      <Card
        title="Disk Usage"
        icon={<HardDrive className="w-5 h-5" />}
        value={disk.usedPercentage}
        subtitle={`${disk.used} / ${disk.total}`}
        chart={{
          data: disk.history,
          color: '#6366F1'
        }}
      />

      <Card
        title="System Uptime"
        icon={<Activity className="w-5 h-5" />}
        value={formatUptime(uptime)}
        subtitle="Since last restart"
      />
    </div>
  );
};

export default SystemStatus;
