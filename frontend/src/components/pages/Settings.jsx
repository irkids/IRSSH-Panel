import React, { useState } from 'react';
import { Save, RefreshCw } from 'lucide-react';
import Button from '../components/common/Button';
import Input from '../components/common/Input';
import Alert from '../components/common/Alert';
import { useApi } from '../services/api';

const Settings = () => {
  const [settings, setSettings] = useState({
    appName: 'IRSSH Panel',
    maxConnections: 1000,
    sessionTimeout: 3600,
    emailNotifications: true,
    loggingLevel: 'info',
    backupEnabled: true,
    backupInterval: 24,
    monitoringEnabled: true
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const api = useApi();

  const handleChange = (field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setSettings(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      await api.put('/settings', settings);
      setSuccess(true);
    } catch (err) {
      setError('Failed to update settings');
    } finally {
      setLoading(false);
    }
  };

  const resetSettings = async () => {
    if (window.confirm('Are you sure you want to reset settings to defaults?')) {
      try {
        setLoading(true);
        const response = await api.post('/settings/reset');
        setSettings(response.data);
        setSuccess(true);
      } catch (err) {
        setError('Failed to reset settings');
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <Button
          variant="light"
          icon={<RefreshCw className="w-4 h-4" />}
          onClick={resetSettings}
          loading={loading}
        >
          Reset to Defaults
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

      {success && (
        <Alert
          variant="success"
          message="Settings updated successfully"
          onClose={() => setSuccess(false)}
          className="mb-4"
        />
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold mb-4">General Settings</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input
              label="Application Name"
              value={settings.appName}
              onChange={handleChange('appName')}
              required
            />
            <Input
              label="Max Connections"
              type="number"
              value={settings.maxConnections}
              onChange={handleChange('maxConnections')}
              required
            />
            <Input
              label="Session Timeout (seconds)"
              type="number"
              value={settings.sessionTimeout}
              onChange={handleChange('sessionTimeout')}
              required
            />
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="emailNotifications"
                checked={settings.emailNotifications}
                onChange={handleChange('emailNotifications')}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <label htmlFor="emailNotifications">
                Enable Email Notifications
              </label>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold mb-4">System Settings</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Logging Level
              </label>
              <select
                value={settings.loggingLevel}
                onChange={handleChange('loggingLevel')}
                className="w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="error">Error</option>
                <option value="warn">Warning</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
              </select>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="backupEnabled"
                checked={settings.backupEnabled}
                onChange={handleChange('backupEnabled')}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <label htmlFor="backupEnabled">
                Enable Automated Backups
              </label>
            </div>
            {settings.backupEnabled && (
              <Input
                label="Backup Interval (hours)"
                type="number"
                value={settings.backupInterval}
                onChange={handleChange('backupInterval')}
                required
              />
            )}
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="monitoringEnabled"
                checked={settings.monitoringEnabled}
                onChange={handleChange('monitoringEnabled')}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <label htmlFor="monitoringEnabled">
                Enable System Monitoring
              </label>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <Button
            type="submit"
            variant="primary"
            icon={<Save className="w-4 h-4" />}
            loading={loading}
          >
            Save Changes
          </Button>
        </div>
      </form>
    </div>
  );
};

export default Settings;
