import React from 'react';

const ProtocolStats = ({ protocols }) => {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold mb-6">Protocol Statistics</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead>
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Online Users</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol port</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incoming Traffic</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Outgoing Traffic</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time Of Being Online</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {protocols.map((protocol, index) => (
              <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.name}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.onlineUsers}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.port}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.incomingTraffic}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.outgoingTraffic}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.timeOnline}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ProtocolStats;
