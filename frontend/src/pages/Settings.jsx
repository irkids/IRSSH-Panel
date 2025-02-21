import React, { useState, useEffect } from 'react';
import { Card, Input, Button, Alert } from '../components/common';
import { Save, RefreshCw } from 'lucide-react';

const Settings = () => {
  const [settings, setSettings] = useState({
    general: {
      appName: '',
      language: 'en',
      timezone: 'UTC'
    },
    security: {
      sessionTimeout: 30,
      maxLoginAttempts: 5,
      passwordExpiration: 90
    },
    notifications: {
      email: true,
      slack: false,
      telegram: false
    },
    monitoring: {
      enabled: true,
      interval: 60,
      retention: 30
    }
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      // Fetch settings from API
      // setSettings(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      // Save settings to API
      setSuccess(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    try {
      setLoading(true);
      // Reset settings to defaults
      await fetchSettings();
      setSuccess(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <Button
          variant="light"
          icon={<RefreshCw className="w-4 h-4" />}
          onClick={handleReset}
          loading={loading}
        >
          Reset to Defaults
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

      {success && (
        <Alert
          variant="success"
          message="Settings saved successfully"
          className="mb-4"
          onClose={() => setSuccess(false)}
        />
      )}

      <form onSubmit={handleSubmit}>
        <div className="space-y-6">
          <Card>
            <h2 className="text-lg font-semibold mb-4">General Settings</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Input
                label="Application Name"
                value={settings.general.appName}
                onChange={(e) => setSettings({
                  ...settings,
                  general: { ...settings.general, appName: e.target.value }
                })}
              />
              {/* Add more general settings */}
            </div>
          </Card>

          <Card>
            <h2 className="text-lg font-semibold mb-4">Security Settings</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Input
                label="Session Timeout (minutes)"
                type="number"
                value={settings.security.sessionTimeout}
                onChange={(e) => setSettings({
                  ...settings,
                  security: { ...settings.security, sessionTimeout: e.target.value }
                })}
              />
              {/* Add more security settings */}
            </div>
          </Card>

          <Card>
            <h2 className="text-lg font-semibold mb-4">Notification Settings</h2>
            <div className="space-y-4">
              {/* Add notification settings */}
            </div>
          </Card>

          <Card>
            <h2 className="text-lg font-semibold mb-4">Monitoring Settings</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Add monitoring settings */}
            </div>
          </Card>

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
        </div>
      </form>
    </div>
  );
};

export default Settings;
