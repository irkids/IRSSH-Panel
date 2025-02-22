import React from 'react';
import { useMetricsContext } from '../context/MetricsContext';

const MetricsTable = () => {
  const { state } = useMetricsContext();
  const { metrics } = state;

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full bg-white rounded-lg shadow">
        <thead>
          <tr className="bg-gray-100">
            <th className="px-6 py-3 text-left">Timestamp</th>
            <th className="px-6 py-3 text-left">CPU (%)</th>
            <th className="px-6 py-3 text-left">Memory (%)</th>
            <th className="px-6 py-3 text-left">Network In (MB/s)</th>
            <th className="px-6 py-3 text-left">Network Out (MB/s)</th>
          </tr>
        </thead>
        <tbody>
          {metrics.history?.map((entry, index) => (
            <tr key={index} className="border-t">
              <td className="px-6 py-4">{entry.timestamp}</td>
              <td className="px-6 py-4">{entry.cpu}</td>
              <td className="px-6 py-4">{entry.memory}</td>
              <td className="px-6 py-4">{entry.network.in}</td>
              <td className="px-6 py-4">{entry.network.out}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default MetricsTable;
