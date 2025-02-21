import React, { useState, useEffect } from 'react';
import { userService } from '../services/users';
import { Card, Input, Button, Alert } from '../components/common';
import { User, Lock, Bell } from 'lucide-react';

const Profile = () => {
  const [profile, setProfile] = useState({
    personal: {
      username: '',
      email: '',
      fullName: ''
    },
    security: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
    },
    preferences: {
      notifications: {
        email: true,
        browser: true
      },
      theme: 'light'
    }
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const data = await userService.getProfile();
      setProfile(prev => ({
        ...prev,
        personal: data
      }));
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
      await userService.updateProfile(profile.personal);
      setSuccess(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async () => {
    try {
      setLoading(true);
      await userService.changePassword(profile.security);
      setSuccess(true);
      setProfile(prev => ({
        ...prev,
        security: {
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        }
      }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">Profile Settings</h1>

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
          message="Profile updated successfully"
          className="mb-4"
          onClose={() => setSuccess(false)}
        />
      )}

      <div className="space-y-6">
        <Card>
          <div className="flex items-center mb-4">
            <User className="w-5 h-5 mr-2" />
            <h2 className="text-lg font-semibold">Personal Information</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input
              label="Username"
              value={profile.personal.username}
              onChange={(e) => setProfile({
                ...profile,
                personal: { ...profile.personal, username: e.target.value }
              })}
            />
            <Input
              label="Email"
              type="email"
              value={profile.personal.email}
              onChange={(e) => setProfile({
                ...profile,
                personal: { ...profile.personal, email: e.target.value }
              })}
            />
            <Input
              label="Full Name"
              value={profile.personal.fullName}
              onChange={(e) => setProfile({
                ...profile,
                personal: { ...profile.personal, fullName: e.target.value }
              })}
            />
          </div>
          <div className="mt-4">
            <Button
              variant="primary"
              loading={loading}
              onClick={handleSubmit}
            >
              Save Changes
            </Button>
          </div>
        </Card>

        <Card>
          <div className="flex items-center mb-4">
            <Lock className="w-5 h-5 mr-2" />
            <h2 className="text-lg font-semibold">Security</h2>
          </div>
          <div className="space-y-4">
            <Input
              label="Current Password"
              type="password"
              value={profile.security.currentPassword}
              onChange={(e) => setProfile({
                ...profile,
                security: { ...profile.security, currentPassword: e.target.value }
              })}
            />
            <Input
              label="New Password"
              type="password"
              value={profile.security.newPassword}
              onChange={(e) => setProfile({
                ...profile,
                security: { ...profile.security, newPassword: e.target.value }
              })}
            />
            <Input
              label="Confirm New Password"
              type="password"
              value={profile.security.confirmPassword}
              onChange={(e) => setProfile({
                ...profile,
                security: { ...profile.security, confirmPassword: e.target.value }
              })}
            />
            <Button
              variant="primary"
              loading={loading}
              onClick={handlePasswordChange}
            >
              Change Password
            </Button>
          </div>
        </Card>

        <Card>
          <div className="flex items-center mb-4">
            <Bell className="w-5 h-5 mr-2" />
            <h2 className="text-lg font-semibold">Preferences</h2>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span>Email Notifications</span>
              <input
                type="checkbox"
                checked={profile.preferences.notifications.email}
                onChange={(e) => setProfile({
                  ...profile,
                  preferences: {
                    ...profile.preferences,
                    notifications: {
                      ...profile.preferences.notifications,
                      email: e.target.checked
                    }
                  }
                })}
                className="form-checkbox h-5 w-5 text-blue-600"
              />
            </div>
            <div className="flex items-center justify-between">
              <span>Browser Notifications</span>
              <input
                type="checkbox"
                checked={profile.preferences.notifications.browser}
                onChange={(e) => setProfile({
                  ...profile,
                  preferences: {
                    ...profile.preferences,
                    notifications: {
                      ...profile.preferences.notifications,
                      browser: e.target.checked
                    }
                  }
                })}
                className="form-checkbox h-5 w-5 text-blue-600"
              />
            </div>
            <div className="flex items-center justify-between">
              <span>Theme</span>
              <select
                value={profile.preferences.theme}
                onChange={(e) => setProfile({
                  ...profile,
                  preferences: {
                    ...profile.preferences,
                    theme: e.target.value
                  }
                })}
                className="form-select mt-1 block w-1/3"
              >
                <option value="light">Light</option>
                <option value="dark">Dark</option>
                <option value="system">System</option>
              </select>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default Profile;
