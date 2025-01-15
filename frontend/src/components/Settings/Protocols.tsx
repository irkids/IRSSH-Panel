// src/components/Settings/Protocols.tsx
import React from 'react';
import { useProtocols, useUpdateProtocolConfig } from '@/hooks/api';

const ProtocolSettings = () => {
  const { data: protocols, isLoading } = useProtocols();
  const { mutate: updateProtocol } = useUpdateProtocolConfig();

  const handleProtocolUpdate = (protocol: string, config: any) => {
    updateProtocol({ protocol, config });
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Protocol Settings</h3>
        <p className="text-sm text-gray-500">Configure protocol-specific settings.</p>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {protocols?.map((protocol: any) => (
          <div key={protocol.name} className="bg-white rounded-lg border border-gray-200 p-4">
            <h4 className="text-md font-medium mb-4">{protocol.name}</h4>
            
            <div className="space-y-4">
              {/* Port Settings */}
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Port
                </label>
                <input
                  type="number"
                  value={protocol.port}
                  onChange={(e) => handleProtocolUpdate(protocol.name, {
                    ...protocol,
                    port: parseInt(e.target.value)
                  })}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
                />
              </div>

              {/* Enable/Disable */}
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={protocol.enabled}
                    onChange={(e) => handleProtocolUpdate(protocol.name, {
                      ...protocol,
                      enabled: e.target.checked
                    })}
                    className="rounded border-gray-300 text-blue-600"
                  />
                  <span className="ml-2 text-sm text-gray-700">Enable {protocol.name}</span>
                </label>
              </div>

              {/* Protocol-specific settings */}
              {protocol.config && Object.entries(protocol.config).map(([key, value]: [string, any]) => (
                <div key={key}>
                  <label className="block text-sm font-medium text-gray-700">
                    {key.replace(/([A-Z])/g, ' $1').charAt(0).toUpperCase() + key.slice(1)}
                  </label>
                  <input
                    type={typeof value === 'number' ? 'number' : 'text'}
                    value={value}
                    onChange={(e) => handleProtocolUpdate(protocol.name, {
                      ...protocol,
                      config: {
                        ...protocol.config,
                        [key]: typeof value === 'number' ? parseInt(e.target.value) : e.target.value
                      }
                    })}
                    className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
                  />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ProtocolSettings;
