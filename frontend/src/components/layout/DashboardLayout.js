// src/components/Layout/DashboardLayout.js
import React from 'react';
import { Link } from 'react-router-dom';
import { Home, Users, Settings, Server } from 'lucide-react';

const Sidebar = () => (
  <div className="w-64 bg-gray-800 min-h-screen p-4">
    <div className="text-white text-xl font-bold mb-8">IRSSH Panel</div>
    <nav>
      <Link to="/dashboard" className="flex items-center text-gray-300 hover:text-white mb-4">
        <Home className="mr-2" size={20} />
        Dashboard
      </Link>
      <Link to="/users" className="flex items-center text-gray-300 hover:text-white mb-4">
        <Users className="mr-2" size={20} />
        Users
      </Link>
      <Link to="/protocols" className="flex items-center text-gray-300 hover:text-white mb-4">
        <Server className="mr-2" size={20} />
        Protocols
      </Link>
      <Link to="/settings" className="flex items-center text-gray-300 hover:text-white mb-4">
        <Settings className="mr-2" size={20} />
        Settings
      </Link>
    </nav>
  </div>
);

export default function DashboardLayout({ children }) {
  return (
    <div className="flex min-h-screen bg-gray-100">
      <Sidebar />
      <div className="flex-1">
        <header className="bg-white shadow">
          <div className="mx-auto px-4 py-6">
            <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          </div>
        </header>
        <main className="mx-auto px-4 py-6">
          {children}
        </main>
      </div>
    </div>
  );
}

// src/components/Dashboard/Overview.js
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
  { name: 'Jan', users: 400 },
  { name: 'Feb', users: 300 },
  { name: 'Mar', users: 600 },
  { name: 'Apr', users: 800 },
  { name: 'May', users: 700 },
];

export default function Overview() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Active Users</h3>
        <p className="mt-2 text-3xl font-bold text-gray-900">246</p>
      </div>
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Total Traffic</h3>
        <p className="mt-2 text-3xl font-bold text-gray-900">1.2 TB</p>
      </div>
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Active Protocols</h3>
        <p className="mt-2 text-3xl font-bold text-gray-900">5</p>
      </div>
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium">Server Load</h3>
        <p className="mt-2 text-3xl font-bold text-gray-900">42%</p>
      </div>
      
      <div className="col-span-full bg-white rounded-lg shadow p-6">
        <h3 className="text-gray-500 text-sm font-medium mb-4">User Growth</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="users" stroke="#3b82f6" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

// src/components/Users/UsersList.js
import React from 'react';
import { PlusIcon } from 'lucide-react';

export default function UsersList() {
  const users = [
    { id: 1, name: 'User 1', email: 'user1@example.com', status: 'Active' },
    { id: 2, name: 'User 2', email: 'user2@example.com', status: 'Inactive' },
  ];

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="p-6 border-b border-gray-200">
        <div className="flex justify-between items-center">
          <h2 className="text-xl font-semibold text-gray-800">Users</h2>
          <button className="bg-blue-500 text-white px-4 py-2 rounded-md flex items-center">
            <PlusIcon size={20} className="mr-2" />
            Add User
          </button>
        </div>
      </div>
      <div className="p-6">
        <table className="min-w-full">
          <thead>
            <tr>
              <th className="text-left py-3 px-4">Name</th>
              <th className="text-left py-3 px-4">Email</th>
              <th className="text-left py-3 px-4">Status</th>
              <th className="text-left py-3 px-4">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id}>
                <td className="py-3 px-4">{user.name}</td>
                <td className="py-3 px-4">{user.email}</td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-1 rounded-full text-xs ${
                    user.status === 'Active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {user.status}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <button className="text-blue-600 hover:text-blue-800 mr-2">Edit</button>
                  <button className="text-red-600 hover:text-red-800">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// src/components/Protocols/ProtocolsList.js
import React from 'react';

export default function ProtocolsList() {
  const protocols = [
    { id: 1, name: 'SSH', status: 'Running', port: 22 },
    { id: 2, name: 'L2TP', status: 'Stopped', port: 1701 },
    { id: 3, name: 'IKEv2', status: 'Running', port: 500 },
  ];

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-xl font-semibold text-gray-800">VPN Protocols</h2>
      </div>
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {protocols.map(protocol => (
            <div key={protocol.id} className="border rounded-lg p-4">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium">{protocol.name}</h3>
                <span className={`px-2 py-1 rounded-full text-xs ${
                  protocol.status === 'Running' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {protocol.status}
                </span>
              </div>
              <div className="text-sm text-gray-500 mb-4">
                Port: {protocol.port}
              </div>
              <div className="flex space-x-2">
                <button className={`px-3 py-1 rounded ${
                  protocol.status === 'Running' 
                    ? 'bg-red-500 text-white hover:bg-red-600'
                    : 'bg-green-500 text-white hover:bg-green-600'
                }`}>
                  {protocol.status === 'Running' ? 'Stop' : 'Start'}
                </button>
                <button className="px-3 py-1 rounded bg-blue-500 text-white hover:bg-blue-600">
                  Configure
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import DashboardLayout from './components/Layout/DashboardLayout';
import Overview from './components/Dashboard/Overview';
import UsersList from './components/Users/UsersList';
import ProtocolsList from './components/Protocols/ProtocolsList';

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/dashboard" element={
          <DashboardLayout>
            <Overview />
          </DashboardLayout>
        } />
        <Route path="/users" element={
          <DashboardLayout>
            <UsersList />
          </DashboardLayout>
        } />
        <Route path="/protocols" element={
          <DashboardLayout>
            <ProtocolsList />
          </DashboardLayout>
        } />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}
