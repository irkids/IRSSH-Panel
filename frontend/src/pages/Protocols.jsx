import React, { useState, useEffect } from 'react';
import { protocolService } from '../services/protocols';
import { Card, Button, Alert } from '../components/common';
import { Settings, Power, Activity } from 'lucide-react';

const Protocols = () => {
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchProtocols();
  }, []);

  const fetchProtocols = async () => {
    try {
      setLoading(true);
      const data = await protocolService.getAllProtocols();
      setProtocols(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (id, enabled) => {
    try {
      await protocolService.toggleProtocol(id, !enabled);
      setProtocols(protocols.map(p => 
        p.id === id ? { ...p, enabled: !enabled } : p
      ));
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Protocols</h1>
        <Button
          variant="primary"
          onClick={() => {/* Handle create */}}
        >
          Add Protocol
        </Button>
      </div>

      {error && (
        <Alert
          variant="error"
          message={error}
          className="mb-4"
          onClose={() => setError(null)}
        />
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div>Loading...</div>
        ) : (
          protocols.map(protocol => (
            <Card key={protocol.id} className="flex flex-col">
              <div className="flex justify-between items-start p-4">
                <div>
                  <h3 className="text-lg font-semibold">{protocol.name}</h3>
                  <p className="text-sm text-gray-500">{protocol.type}</p>
                </div>
                <Button
                  variant={protocol.enabled ? 'success' : 'light'}
                  size="sm"
                  icon={<Power className="w-4 h-4" />}
                  onClick={() => handleToggle(protocol.id, protocol.enabled)}
                >
                  {protocol.enabled ? 'Enabled' : 'Disabled'}
                </Button>
              </div>

              <div className="p-4 border-t border-gray-100">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-500">Connections</p>
                    <p className="text-lg font-semibold">
                      {protocol.connections?.current}/{protocol.connections?.max}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Bandwidth</p>
                    <p className="text-lg font-semibold">
                      {formatBandwidth(protocol.bandwidth)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-gray-50 rounded-b-lg flex justify-between">
                <Button
                  variant="light"
                  size="sm"
                  icon={<Settings className="w-4 h-4" />}
                  onClick={() => {/* Handle configure */}}
                >
                  Configure
                </Button>
                <Button
                  variant="light"
                  size="sm"
                  icon={<Activity className="w-4 h-4" />}
                  onClick={() => {/* Handle metrics */}}
                >
                  Metrics
                </Button>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};

const formatBandwidth = (bytes) => {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
};

export default Protocols;
