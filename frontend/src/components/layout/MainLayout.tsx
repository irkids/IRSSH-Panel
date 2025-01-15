// frontend/src/components/layout/MainLayout.tsx

import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Users, 
  UserPlus,
  Settings, 
  LogOut,
  ChevronDown,
  ChevronRight,
  Moon,
  Sun
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';

const MainLayout = () => {
  const [openSubmenu, setOpenSubmenu] = useState<string | null>(null);
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  const menuItems = [
    { 
      id: 'dashboard',
      label: 'Dashboard',
      icon: <LayoutDashboard className="w-5 h-5" />,
      href: '/dashboard'
    },
    {
      id: 'user-management',
      label: 'User Management',
      icon: <Users className="w-5 h-5" />,
      submenu: [
        { id: 'ssh', label: 'SSH Users', href: '/users/ssh' },
        { id: 'l2tp', label: 'L2TP Users', href: '/users/l2tp' },
        { id: 'ikev2', label: 'IKEv2 Users', href: '/users/ikev2' },
        { id: 'cisco', label: 'Cisco AnyConnect Users', href: '/users/cisco' },
        { id: 'wireguard', label: 'WireGuard Users', href: '/users/wireguard' },
        { id: 'singbox', label: 'SingBox Users', href: '/users/singbox' }
      ]
    },
    {
      id: 'online-users',
      label: 'Online Users',
      icon: <UserPlus className="w-5 h-5" />,
      href: '/online-users'
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: <Settings className="w-5 h-5" />,
      href: '/settings'
    }
  ];

  const toggleSubmenu = (id: string) => {
    setOpenSubmenu(openSubmenu === id ? null : id);
  };

  return (
    <div className="flex h-screen bg-white dark:bg-gray-900">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-50 dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700">
        {/* Logo Area */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-700">
          <span className="text-xl font-bold text-gray-800 dark:text-white">IRSSH</span>
          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            {theme === 'dark' ? (
              <Sun className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            ) : (
              <Moon className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            )}
          </button>
        </div>

        {/* User Info */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-medium">
                {user?.username?.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-700 dark:text-white">
                {user?.username}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {user?.role || 'Administrator'}
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="mt-4">
          <ul className="space-y-1">
            {menuItems.map((item) => (
              <li key={item.id}>
                {item.submenu ? (
                  <div>
                    <button
                      onClick={() => toggleSubmenu(item.id)}
                      className="w-full flex items-center justify-between px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                    >
                      <div className="flex items-center">
                        {item.icon}
                        <span className="ml-3">{item.label}</span>
                      </div>
                      {openSubmenu === item.id ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </button>
                    {openSubmenu === item.id && (
                      <ul className="mt-1 pl-8 space-y-1">
                        {item.submenu.map((subitem) => (
                          <li key={subitem.id}>
                            <a
                              href={subitem.href}
                              className="block px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                            >
                              {subitem.label}
                            </a>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ) : (
                  <a
                    href={item.href}
                    className="flex items-center px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    {item.icon}
                    <span className="ml-3">{item.label}</span>
                  </a>
                )}
              </li>
            ))}

            {/* Logout Button */}
            <li>
              <button
                onClick={logout}
                className="w-full flex items-center px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20"
              >
                <LogOut className="w-5 h-5" />
                <span className="ml-3">Logout</span>
              </button>
            </li>
          </ul>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-gray-50 dark:bg-gray-900">
        <Outlet />
      </main>
    </div>
  );
};

export default MainLayout;
