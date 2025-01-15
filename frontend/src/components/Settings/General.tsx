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
