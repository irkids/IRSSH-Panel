import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { Card } from '../../../components/common';

const ProtocolStatus = ({ protocols }) => {
  return (
    <Card title="Protocol Status">
      <div className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
          {protocols.map(protocol => (
            <div
              key={protocol._id}
              className="bg-white rounded-lg shadow p-4"
            >
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-lg font-semibold">{protocol.name}</h3>
                <span className={`px-2 py-1 rounded-full text-sm ${
                  protocol.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {protocol.enabled ? 'Active' : 'Inactive'}
                </span>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Connections</span>
                  <span>{protocol.currentConnections}/{protocol.maxConnections}</span>
                </div>
                
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Bandwidth</span>
                  <span>{protocol.bandwidth.toFixed(2)} MB/s</span>
                </div>
                
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Errors</span>
                  <span className={protocol.errors > 0 ? 'text-red-600' : ''}>
                    {protocol.errors}
                  </span>
                </div>
              </div>

              <div className="mt-4 h-32">
                <LineChart data={protocol.history} width={300} height={120}>
                  <XAxis dataKey="time" hide />
                  <YAxis hide />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="connections"
                    stroke="#3B82F6"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
};

export default ProtocolStatus;
