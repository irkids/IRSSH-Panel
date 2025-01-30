import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { IconUsers, IconSettings } from '../components/Common/Icons';

const MenuItem = ({ href, icon: Icon, label, active = false }) => (
  <Link
    to={href}
    className={`flex items-center px-4 py-2 text-sm space-x-3 rounded-md ${
      active
        ? 'bg-gray-900 text-white'
        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
    }`}
  >
    {Icon && <Icon className="w-5 h-5" />}
    <span>{label}</span>
  </Link>
);

const Sidebar = () => {
  const location = useLocation();
  const isActive = (path) => location.pathname === path;

  return (
    <div className="hidden md:flex md:flex-shrink-0">
      <div className="flex flex-col w-64">
        <div className="flex flex-col h-0 flex-1">
          <div className="flex items-center h-16 flex-shrink-0 px-4 bg-gray-900">
            <img
              className="h-8 w-auto"
              src="/logo.png"
              alt="IRSSH"
            />
            <span className="ml-2 text-white text-lg font-semibold">IRSSH Panel</span>
          </div>
          <div className="flex-1 flex flex-col overflow-y-auto bg-gray-800">
            <nav className="flex-1 px-2 py-4 space-y-1">
              <MenuItem
                href="/dashboard"
                icon={IconSettings}
                label="Dashboard"
                active={isActive('/dashboard')}
              />
              <MenuItem
                href="/users"
                icon={IconUsers}
                label="User Management"
                active={isActive('/users')}
              />
              <div className="pt-4 mt-4 space-y-1 border-t border-gray-700">
                <MenuItem
                  href="/settings"
                  icon={IconSettings}
                  label="Settings"
                  active={isActive('/settings')}
                />
              </div>
            </nav>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
