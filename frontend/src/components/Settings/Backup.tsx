// src/components/Settings/General.tsx
import React from 'react';
import { useSystemSettings, useUpdateSystemSettings } from '@/hooks/api';

const GeneralSettings = () => {
  const { data: settings, isLoading } = useSystemSettings();
  const { mutate: updateSettings } = useUpdateSystemSettings();

  const handleSubmit = (data: any) => {
    updateSettings(data);
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">General Settings</h3>
        <p className="text-sm text-gray-500">Configure general system settings.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 gap-6">
          {/* Server Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Server Name
            </label>
            <input
              type="text"
              name="serverName"
              defaultValue={settings?.serverName}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
            />
          </div>

          {/* Language */}
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Language
            </label>
            <select
              name="language"
              defaultValue={settings?.language}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
            >
              <option value="en">English</option>
              <option value="fa">Persian</option>
            </select>
          </div>

          {/* Timezone */}
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Timezone
            </label>
            <select
              name="timezone"
              defaultValue={settings?.timezone}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
            >
              <option value="UTC">UTC</option>
              <option value="Asia/Tehran">Asia/Tehran</option>
              {/* Add more timezones */}
            </select>
          </div>

          {/* Auto Update */}
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                name="autoUpdate"
                defaultChecked={settings?.autoUpdate}
                className="rounded border-gray-300 text-blue-600"
              />
              <span className="ml-2 text-sm text-gray-700">Enable Auto Updates</span>
            </label>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Save Changes
          </button>
        </div>
      </form>
    </div>
  );
};

export default GeneralSettings;

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

// src/components/Settings/Backup.tsx
import React from 'react';
import { useBackups, useCreateBackup } from '@/hooks/api';

const BackupSettings = () => {
  const { data: backups, isLoading } = useBackups();
  const { mutate: createBackup } = useCreateBackup();

  const handleCreateBackup = (config: any) => {
    createBackup(config);
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Backup & Restore</h3>
        <p className="text-sm text-gray-500">Manage system backups and restoration.</p>
      </div>

      {/* Create Backup */}
      <div className="bg-white rounded-lg border border-gray-200 p-4">
        <h4 className="text-md font-medium mb-4">Create Backup</h4>
        <form onSubmit={(e) => {
          e.preventDefault();
          const formData = new FormData(e.currentTarget);
          handleCreateBackup({
            components: Array.from(formData.getAll('components')),
            notes: formData.get('notes'),
            cleanup: formData.get('cleanup') === 'true',
            telegram: formData.get('telegram') === 'true'
          });
        }}>
          <div className="space-y-4">
            {/* Backup Components */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Components to Backup
              </label>
              <div className="space-y-2">
                {['database', 'config', 'certificates', 'logs'].map((component) => (
                  <label key={component} className="flex items-center">
                    <input
                      type="checkbox"
                      name="components"
                      value={component}
                      className="rounded border-gray-300 text-blue-600"
                    />
                    <span className="ml-2 text-sm text-gray-700 capitalize">{component}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Notes */}
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Backup Notes
              </label>
              <textarea
                name="notes"
                rows={3}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2"
                placeholder="Optional notes about this backup"
              />
            </div>

            {/* Options */}
            <div className="space-y-2">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  name="cleanup"
                  value="true"
                  className="rounded border-gray-300 text-blue-600"
                />
                <span className="ml-2 text-sm text-gray-700">
                  Clean up old backups
                </span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  name="telegram"
                  value="true"
                  className="rounded border-gray-300 text-blue-600"
                />
                <span className="ml-2 text-sm text-gray-700">
                  Send to Telegram
                </span>
              </label>
            </div>

            <button
              type="submit"
              className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Create Backup
            </button>
          </div>
        </form>
      </div>

      {/* Backup History */}
      <div className="bg-white rounded-lg border border-gray-200 p-4">
        <h4 className="text-md font-medium mb-4">Backup History</h4>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Date
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Size
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Components
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {backups?.map((backup: any) => (
                <tr key={backup.id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {new Date(backup.created_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {(backup.size / (1024 * 1024)).toFixed(2)} MB
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex flex-wrap gap-1">
                      {backup.components.map((component: string) => (
                        <span
                          key={component}
                          className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800"
                        >
                          {component}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      backup.status === 'completed'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {backup.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => {/* Download backup */}}
                      className="text-blue-600 hover:text-blue-900 mr-4"
                    >
                      Download
                    </button>
                    <button
                      onClick={() => {/* Delete backup */}}
                      className="text-red-600 hover:text-red-900"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default BackupSettings;
