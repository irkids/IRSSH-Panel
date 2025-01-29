import React, { useEffect, useState } from 'react';
import axios from '../../config/axios';
import { Line } from 'recharts';
import { removeToken } from '../../utils/auth';

const Dashboard = () => {
  const [serverInfo, setServerInfo] = useState({
    cpu: 0,
    ram: 0,
    disk: 0
  });
  const [bandwidthData, setBandwidthData] = useState({
    monthly: [],
    daily: []
  });
  const [userStats, setUserStats] = useState({
    active: 0,
    expired: 0,
    expiredSoon: 0,
    deactive: 0,
    online: 0,
    total: 0
  });
  const [protocolStats, setProtocolStats] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/monitoring/system');
        setServerInfo({
          cpu: response.data.cpu || 0,
          ram: response.data.ram || 0,
          disk: response.data.disk || 0
        });

        // Additional API calls for other data would go here
        // These are placeholders until the backend endpoints are implemented
        setProtocolStats([
          {
            protocol: 'SSH',
            onlineUsers: 3,
            port: 22,
            incomingTraffic: '1.2 Mbps',
            outgoingTraffic: '0.8 Mbps',
            timeOnline: '2023-10-14 10:00:00'
          },
          {
            protocol: 'WireGuard',
            onlineUsers: 2,
            port: 10582,
            incomingTraffic: '0.5 Mbps',
            outgoingTraffic: '0.3 Mbps',
            timeOnline: '2023-10-14 11:30:00'
          },
          {
            protocol: 'SingBox',
            onlineUsers: 2,
            port: 1049,
            incomingTraffic: '0.3 Mbps',
            outgoingTraffic: '0.2 Mbps',
            timeOnline: '2023-10-14 12:45:00'
          },
          {
            protocol: 'Cisco',
            onlineUsers: 1,
            port: 85,
            incomingTraffic: '0.3 Mbps',
            outgoingTraffic: '0.2 Mbps',
            timeOnline: '2023-10-14 12:45:00'
          },
          {
            protocol: 'IKEv2',
            onlineUsers: 1,
            port: 49500,
            incomingTraffic: '0.3 Mbps',
            outgoingTraffic: '0.2 Mbps',
            timeOnline: '2023-10-14 12:45:00'
          }
        ]);

      } catch (err) {
        console.error('Error fetching data:', err);
        setError('Failed to load dashboard data');
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    removeToken();
    window.location.href = '/login';
  };

  const ResourceCircle = ({ value, label, icon }) => (
    <div className="flex flex-col items-center">
      <div className="relative w-32 h-32">
        <svg className="w-full h-full" viewBox="0 0 100 100">
          <circle
            className="text-gray-200 stroke-current"
            strokeWidth="10"
            cx="50"
            cy="50"
            r="40"
            fill="none"
          />
          <circle
            className="text-green-500 progress-ring stroke-current"
            strokeWidth="10"
            strokeLinecap="round"
            cx="50"
            cy="50"
            r="40"
            fill="none"
            strokeDasharray={`${value * 2.51} 251`}
            transform="rotate(-90 50 50)"
          />
          <text
            x="50"
            y="50"
            className="text-2xl font-bold"
            textAnchor="middle"
            dy=".3em"
          >
            {value}%
          </text>
        </svg>
        <div className="mt-2 text-center">
          <span className="text-gray-700">{label}</span>
          <div className="mt-1">{icon}</div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <img src="/logo.png" alt="IRSSH" className="h-8 w-8 mr-2" />
              <h1 className="text-xl font-bold">Dashboard</h1>
            </div>
            <div className="flex items-center">
              <button
                onClick={handleLogout}
                className="bg-red-600 px-4 py-2 text-white rounded-md hover:bg-red-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {error ? (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        ) : (
          <>
            {/* Server Resource Statistics */}
            <div className="bg-white rounded-lg shadow p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Server Resource Statistics</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <ResourceCircle
                  value={serverInfo.cpu}
                  label="CPU Usage"
                  icon={<svg className="w-6 h-6" />}
                />
                <ResourceCircle
                  value={serverInfo.ram}
                  label="RAM Usage"
                  icon={<svg className="w-6 h-6" />}
                />
                <ResourceCircle
                  value={serverInfo.disk}
                  label="Disk Usage"
                  icon={<svg className="w-6 h-6" />}
                />
              </div>
            </div>

            {/* Protocol Statistics */}
            <div className="bg-white rounded-lg shadow p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Protocol Statistics</h2>
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="bg-gray-50">
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Online Users</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol port</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incoming Traffic</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Outgoing Traffic</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time Of Being Online</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {protocolStats.map((stat, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.protocol}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.onlineUsers}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.port}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.incomingTraffic}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.outgoingTraffic}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{stat.timeOnline}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Users Statistics */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Users Statistics</h2>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center">
                  <div className="text-green-600">Active</div>
                  <div className="text-2xl font-bold">{userStats.active}</div>
                </div>
                <div className="text-center">
                  <div className="text-red-600">Expired</div>
                  <div className="text-2xl font-bold">{userStats.expired}</div>
                </div>
                <div className="text-center">
                  <div className="text-yellow-600">Expired in 24 hours</div>
                  <div className="text-2xl font-bold">{userStats.expiredSoon}</div>
                </div>
                <div className="text-center">
                  <div className="text-gray-600">Deactive</div>
                  <div className="text-2xl font-bold">{userStats.deactive}</div>
                </div>
                <div className="text-center">
                  <div className="text-blue-600">Online</div>
                  <div className="text-2xl font-bold">{userStats.online}</div>
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
};

export default Dashboard;
