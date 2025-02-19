import React, { useState, useEffect } from 'react';
import { Plus, Settings, Power } from 'lucide-react';
import Button from '../components/common/Button';
import Alert from '../components/common/Alert';
import { useApi } from '../services/api';

const Protocols = () => {
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const api = useApi();

  useEffect(() => {
    fetchProtocols();
  }, []);

  const fetchProtocols = async () => {
    try {
      setLoading(true);
      const response = await api.get('/protocols');
      setProtocols(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch protocols');
    } finally {
      setLoading(false);
    }
  };

  const toggleProtocol = async (id, enabled) => {
    try {
      await api.put(`/protocols/${id}`, { enabled: !enabled });
      setProtocols(protocols.map(p =>
        p._id === id ? { ...p, enabled: !enabled } : p
      ));
    } catch (err) {
      setError('Failed to toggle protocol');
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Protocols</h1>
        <Button
          variant="primary"
          icon={<Plus className="w-4 h-4" />}
          onClick={() => {/* Implement create protocol */}}
        >
          Add Protocol
        </Button>
      </div>

      {error && (
        <Alert
          variant="error"
          message={error}
          onClose={() => setError(null)}
          className="mb-4"
        />
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full text-center">Loading...</div>
        ) : protocols.length === 0 ? (
          <div className="col-span-full text-center">No protocols found</div>
        ) : (
          protocols.map((protocol) => (
            <div
              key={protocol._id}
              className="bg-white rounded-lg shadow-md p-6"
            >
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold">{protocol.name}</h3>
                  <p className="text-sm text-gray-500">{protocol.type}</p>
                </div>
                <Button
                  variant={protocol.enabled ? 'success' : 'light'}
                  size="sm"
                  icon={<Power className="w-4 h-4" />}
                  onClick={() => toggleProtocol(protocol._id, protocol.enabled)}
                >
                  {protocol.enabled ? 'Enabled' : 'Disabled'}
                </Button>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Port</span>
                  <span className="font-medium">{protocol.config.port}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Connections</span>
                  <span className="font-medium">
                    {protocol.currentConnections}/{protocol.maxConnections}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Encryption</span>
                  <span className="font-medium">
                    {protocol.settings.encryption}
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-100">
                <Button
                  variant="light"
                  size="sm"
                  icon={<Settings className="w-4 h-4" />}
                  className="w-full"
                  onClick={() => {/* Implement settings */}}
                >
                  Configure
                </Button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Protocols;
