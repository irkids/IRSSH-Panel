// src/components/settings/LocationTracker.tsx
import React, { useState, useEffect } from 'react';
import { Map, Lock, Unlock, Globe, Star, Shield } from 'lucide-react';
import { toast } from 'react-hot-toast';
import axios from '@/lib/axios';

interface LocationData {
  country: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
}

const LocationTracker: React.FC = () => {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [isActivated, setIsActivated] = useState(false);
  const [activationCode, setActivationCode] = useState('');
  const [locationData, setLocationData] = useState<LocationData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkModuleStatus();
  }, []);

  const checkModuleStatus = async () => {
    try {
      const response = await axios.get('/settings/location-tracker/status');
      setIsUnlocked(response.data.unlocked);
      setIsActivated(response.data.activated);
    } catch (error) {
      console.error('Error checking module status:', error);
    }
  };

  const handleActivation = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await axios.post('/settings/location-tracker/activate', {
        activationCode
      });

      if (response.data.success) {
        setIsActivated(true);
        toast.success('Location Tracker activated successfully');
        setActivationCode('');
      } else {
        setError(response.data.message || 'Activation failed');
        toast.error('Activation failed');
      }
    } catch (error: any) {
      setError(error.response?.data?.message || 'Activation failed');
      toast.error('Activation failed');
    } finally {
      setLoading(false);
    }
  };

  const fetchLocation = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await axios.get('/settings/location-tracker/location');
      setLocationData(response.data);
    } catch (error: any) {
      setError(error.response?.data?.message || 'Failed to fetch location data');
      toast.error('Failed to fetch location data');
    } finally {
      setLoading(false);
    }
  };

  if (!isUnlocked) {
    return (
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-6">
        <div className="flex items-center space-x-3">
          <Lock className="w-6 h-6 text-gray-400" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">VIP Feature: Location Tracker</h3>
            <p className="text-sm text-gray-500">
              This feature requires a valid license. Please contact support to unlock.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!isActivated) {
    return (
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <div className="flex items-center space-x-3 mb-6">
          <Shield className="w-6 h-6 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Activate Location Tracker</h3>
            <p className="text-sm text-gray-500">
              Enter your activation code to enable the Location Tracker feature.
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Activation Code
            </label>
            <div className="mt-1">
              <input
                type="text"
                value={activationCode}
                onChange={(e) => setActivationCode(e.target.value)}
                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                placeholder="Enter your activation code"
              />
            </div>
          </div>

          {error && (
            <div className="text-sm text-red-600">
              {error}
            </div>
          )}

          <button
            onClick={handleActivation}
            disabled={loading || !activationCode}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loading ? 'Activating...' : 'Activate Feature'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Globe className="w-6 h-6 text-green-500" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Location Tracker</h3>
            <p className="text-sm text-gray-500">
              View detailed location information for connected clients.
            </p>
          </div>
        </div>
        <Star className="w-5 h-5 text-yellow-400" />
      </div>

      {locationData ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Location Details</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs text-gray-500">Country</dt>
                  <dd className="text-sm font-medium">{locationData.country}</dd>
                </div>
                <div>
                  <dt className="text-xs text-gray-500">Region</dt>
                  <dd className="text-sm font-medium">{locationData.region}</dd>
                </div>
                <div>
                  <dt className="text-xs text-gray-500">City</dt>
                  <dd className="text-sm font-medium">{locationData.city}</dd>
                </div>
              </dl>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Network Details</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs text-gray-500">ISP</dt>
                  <dd className="text-sm font-medium">{locationData.isp}</dd>
                </div>
                <div>
                  <dt className="text-xs text-gray-500">Organization</dt>
                  <dd className="text-sm font-medium">{locationData.org}</dd>
                </div>
              </dl>
            </div>
          </div>

          <div className="h-64 bg-gray-100 rounded-lg">
            {/* Map component would go here */}
            <div className="flex items-center justify-center h-full text-gray-500">
              <Map className="w-6 h-6 mr-2" />
              Map View
            </div>
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-12">
          <button
            onClick={fetchLocation}
            disabled={loading}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Globe className="w-5 h-5 mr-2" />
            {loading ? 'Fetching...' : 'Get Location Data'}
          </button>
          {error && (
            <p className="mt-2 text-sm text-red-600">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default LocationTracker;
