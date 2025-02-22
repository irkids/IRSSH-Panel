import React from 'react';
import { useMetricsContext } from '../context/MetricsContext';

const MetricsSummary = () => {
  const { state } = useMetricsContext();
  const { metrics } = state;

  return (
    <div className="grid grid-cols-4 gap-4 p-4">
      <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold">CPU Usage</h3>
        <p className="text-2xl mt-2">{metrics.cpu}%</p>
      </div>
      <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold">Memory Usage</h3>
        <p className="text-2xl mt-2">{metrics.memory}%</p>
      </div>
      <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold">Network In</h3>
        <p className="text-2xl mt-2">{metrics.network.in} MB/s</p>
      </div>
      <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold">Network Out</h3>
        <p className="text-2xl mt-2">{metrics.network.out} MB/s</p>
      </div>
    </div>
  );
};

export default MetricsSummary;
