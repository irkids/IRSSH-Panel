#!/bin/bash

# Setup frontend
setup_frontend() {
    log "Setting up frontend..."
    cd "$FRONTEND_DIR"

    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.4.5",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "recharts": "^2.5.0",
    "clsx": "^1.2.1",
    "react-scripts": "5.0.1",
    "@babel/plugin-proposal-private-property-in-object": "^7.21.11",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "GENERATE_SOURCEMAP=false react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ]
  }
}
EOL

    # Create index.html
    cat > public/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <title>IRSSH Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
EOL

    # Create axios config
    cat > src/config/axios.js << 'EOL'
import axios from 'axios';

const instance = axios.create({
    baseURL: '/',
    timeout: 5000,
});

instance.interceptors.request.use(
    config => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    error => Promise.reject(error)
);

instance.interceptors.response.use(
    response => response,
    error => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

export default instance;
EOL

    # Create auth utils
    cat > src/utils/auth.js << 'EOL'
export const setToken = (token) => {
    localStorage.setItem('token', token);
};

export const getToken = () => {
    return localStorage.getItem('token');
};

export const removeToken = () => {
    localStorage.removeItem('token');
};

export const isAuthenticated = () => {
    return !!getToken();
};
EOL

    # Create layout components
    mkdir -p src/layouts
    cat > src/layouts/MainLayout.js << 'EOL'
import React from 'react';
import Sidebar from '../components/Sidebar';

const MainLayout = ({ children }) => {
  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar />
      <div className="flex-1 overflow-auto">
        {children}
      </div>
    </div>
  );
};

export default MainLayout;
EOL

    cat > src/components/Sidebar.js << 'EOL'
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { removeToken } from '../utils/auth';
import clsx from 'clsx';

const MenuItem = ({ icon, label, to, children, isActive }) => {
  const [isOpen, setIsOpen] = React.useState(false);

  return (
    <div>
      <Link
        to={to}
        className={clsx(
          'flex items-center px-4 py-2 text-sm rounded-lg mx-2',
          isActive
            ? 'bg-indigo-100 text-indigo-700'
            : 'text-gray-700 hover:bg-gray-100'
        )}
        onClick={() => setIsOpen(!isOpen)}
      >
        {icon}
        <span className="ml-3">{label}</span>
        {children && (
          <svg
            className={`w-4 h-4 ml-auto transform ${isOpen ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        )}
      </Link>
      {children && isOpen && (
        <div className="ml-8 mt-2 space-y-1">{children}</div>
      )}
    </div>
  );
};

const Sidebar = () => {
  const location = useLocation();
  const handleLogout = () => {
    removeToken();
    window.location.href = '/login';
  };

  return (
    <div className="w-64 bg-white shadow-md">
      <div className="h-16 flex items-center px-4">
        <img src="/logo.png" alt="IRSSH" className="h-8 w-8" />
        <div className="ml-2">
          <div className="text-xl font-bold">IRSSH Panel</div>
          <div className="text-sm text-gray-500">Administrator</div>
        </div>
      </div>
      <div className="px-2 py-4">
        <div className="space-y-1">
          <MenuItem
            to="/dashboard"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>}
            label="Dashboard"
            isActive={location.pathname === '/dashboard'}
          />
          <MenuItem
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>}
            label="User Management"
          >
            <MenuItem
              to="/users/ssh"
              label="SSH Users"
              isActive={location.pathname === '/users/ssh'}
            />
            <MenuItem
              to="/users/l2tp"
              label="L2TP Users"
              isActive={location.pathname === '/users/l2tp'}
            />
            <MenuItem
              to="/users/ikev2"
              label="IKEv2 Users"
              isActive={location.pathname === '/users/ikev2'}
            />
            <MenuItem
              to="/users/cisco"
              label="Cisco Users"
              isActive={location.pathname === '/users/cisco'}
            />
            <MenuItem
              to="/users/wireguard"
              label="WireGuard Users"
              isActive={location.pathname === '/users/wireguard'}
            />
            <MenuItem
              to="/users/singbox"
              label="SingBox Users"
              isActive={location.pathname === '/users/singbox'}
            />
            <MenuItem
              to="/users/all"
              label="All Users"
              isActive={location.pathname === '/users/all'}
            />
          </MenuItem>
          <MenuItem
            to="/online"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
            </svg>}
            label="Online Users"
            isActive={location.pathname === '/online'}
          />
          <MenuItem
            to="/settings"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>}
            label="Settings"
            isActive={location.pathname === '/settings'}
          />
          <button
            onClick={handleLogout}
            className="w-full text-left flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg mx-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
            <span className="ml-3">Logout</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
EOL

    # Create Dashboard components
    mkdir -p src/components/Dashboard
    cat > src/components/Dashboard/ResourceStats.js << 'EOL'
import React from 'react';

const ResourceCircle = ({ value, label, icon }) => (
    <div className="relative w-32 h-32 mx-auto">
        <svg className="w-full h-full transform -rotate-90">
            <circle
                cx="64"
                cy="64"
                r="60"
                fill="none"
                stroke="#e5e7eb"
                strokeWidth="8"
            />
            <circle
                cx="64"
                cy="64"
                r="60"
                fill="none"
                stroke="#10b981"
                strokeWidth="8"
                strokeDasharray={`${value * 3.77} 377`}
                strokeLinecap="round"
            />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center flex-col">
            <span className="text-2xl font-bold">{value}%</span>
            <span className="text-sm text-gray-500">{label}</span>
            {icon}
        </div>
    </div>
);

const ResourceStats = ({ cpuUsage, ramUsage, diskUsage }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Server Resource Statistics</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <ResourceCircle
                    value={cpuUsage}
                    label="CPU Usage"
                    icon={<svg className="w-6 h-6 mt-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                            d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                    </svg>}
                />
                <ResourceCircle
                    value={ramUsage}
                    label="RAM Usage"
                    icon={<svg className="w-6 h-6 mt-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                            d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>}
                />
                <ResourceCircle
                    value={diskUsage}
                    label="Disk Usage"
                    icon={<svg className="w-6 h-6 mt-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                            d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                    </svg>}
                />
            </div>
        </div>
    );
};

export default ResourceStats;
EOL

    cat > src/components/Dashboard/BandwidthStats.js << 'EOL'
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const BandwidthStats = ({ monthlyData, dailyData }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Bandwidth Statistics</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                    <h3 className="text-lg font-medium mb-4">Monthly Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={monthlyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" name="Send" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" name="Receive" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" name="Total" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div>
                    <h3 className="text-lg font-medium mb-4">Daily Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={dailyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" name="Send" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" name="Receive" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" name="Total" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default BandwidthStats;
EOL

    cat > src/components/Dashboard/ProtocolStats.js << 'EOL'
import React from 'react';

const ProtocolStats = ({ protocols }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Protocol Statistics</h2>
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead>
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Online Users</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol port</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incoming Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Outgoing Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time Of Being Online</th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {protocols.map((protocol, index) => (
                            <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.name}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.onlineUsers}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.port}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.incomingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.outgoingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{protocol.timeOnline}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ProtocolStats;
EOL

    cat > src/components/Dashboard/UserStats.js << 'EOL'
import React from 'react';

const StatBox = ({ label, value, color }) => (
    <div className="text-center">
        <div className={`text-${color}-600 font-medium`}>{label}</div>
        <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
);

const UserStats = ({ stats }) => {
    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6">Users Statistics</h2>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <StatBox label="Active" value={stats.active} color="green" />
                <StatBox label="Expired" value={stats.expired} color="red" />
                <StatBox label="Expired in 24h" value={stats.expiredSoon} color="yellow" />
                <StatBox label="Deactive" value={stats.deactive} color="gray" />
                <StatBox label="Online" value={stats.online} color="blue" />
            </div>
        </div>
    );
};

export default UserStats;
EOL

    cat > src/components/Dashboard/index.js << 'EOL'
import React, { useState, useEffect } from 'react';
import axios from '../../config/axios';
import ResourceStats from './ResourceStats';
import BandwidthStats from './BandwidthStats';
import ProtocolStats from './ProtocolStats';
import UserStats from './UserStats';
import MainLayout from '../../layouts/MainLayout';

const Dashboard = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [data, setData] = useState({
        resources: { cpu: 0, ram: 0, disk: 0 },
        bandwidth: {
            monthly: [],
            daily: []
        },
        protocols: [],
        users: {
            active: 0,
            expired: 0,
            expiredSoon: 0,
            deactive: 0,
            online: 0
        }
    });

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('/api/monitoring/system');
                setData(response.data);
                setError(null);
            } catch (err) {
                console.error('Error fetching dashboard data:', err);
                setError('Failed to load dashboard data');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
                </div>
            </MainLayout>
        );
    }

    if (error) {
        return (
            <MainLayout>
                <div className="flex justify-center items-center h-full">
                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                        {error}
                    </div>
                </div>
            </MainLayout>
        );
    }

    return (
        <MainLayout>
            <div className="p-6 space-y-6">
                <ResourceStats
                    cpuUsage={data.resources.cpu}
                    ramUsage={data.resources.ram}
                    diskUsage={data.resources.disk}
                />
                <BandwidthStats
                    monthlyData={data.bandwidth.monthly}
                    dailyData={data.bandwidth.daily}
                />
                <ProtocolStats protocols={data.protocols} />
                <UserStats stats={data.users} />
            </div>
        </MainLayout>
    );
};

export default Dashboard;
EOL

    # Install dependencies and build
    log "Installing frontend dependencies..."
    npm install

    log "Building frontend..."
    GENERATE_SOURCEMAP=false npm run build

    if [ $? -eq 0 ]; then
        log "Frontend built successfully"
    else
        error "Frontend build failed"
    fi
}
