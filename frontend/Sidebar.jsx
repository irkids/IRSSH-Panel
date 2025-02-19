import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  Users, 
  Settings, 
  Shield, 
  Activity,
  Server,
  BarChart2,
  AlertTriangle,
  LogOut
} from 'lucide-react';

const Sidebar = () => {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  const menuItems = [
    { path: '/dashboard', icon: Home, label: 'Dashboard' },
    { path: '/users', icon: Users, label: 'Users' },
    { path: '/protocols', icon: Server, label: 'Protocols' },
    { path: '/security', icon: Shield, label: 'Security' },
    { path: '/monitoring', icon: Activity, label: 'Monitoring' },
    { path: '/analytics', icon: BarChart2, label: 'Analytics' },
    { path: '/logs', icon: AlertTriangle, label: 'Logs' },
    { path: '/settings', icon: Settings, label: 'Settings' }
  ];

  return (
    <div className={`sidebar bg-gray-800 text-white h-screen ${collapsed ? 'w-16' : 'w-64'} transition-all duration-300`}>
      <div className="flex items-center justify-between p-4 border-b border-gray-700">
        {!collapsed && <h1 className="text-xl font-bold">IRSSH Panel</h1>}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-2 rounded hover:bg-gray-700"
        >
          {collapsed ? '→' : '←'}
        </button>
      </div>

      <nav className="mt-6">
        {menuItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`
              flex items-center px-4 py-3 transition-colors
              ${location.pathname === item.path ? 'bg-gray-700' : 'hover:bg-gray-700'}
            `}
          >
            <item.icon className="w-5 h-5" />
            {!collapsed && <span className="ml-3">{item.label}</span>}
          </Link>
        ))}
      </nav>

      <div className="absolute bottom-0 w-full p-4 border-t border-gray-700">
        <button
          className="flex items-center w-full px-4 py-2 text-red-400 hover:bg-gray-700 rounded"
          onClick={() => {/* Implement logout */}}
        >
          <LogOut className="w-5 h-5" />
          {!collapsed && <span className="ml-3">Logout</span>}
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
