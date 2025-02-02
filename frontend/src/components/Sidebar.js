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
        <span className="ml-2 text-xl font-bold">IRSSH Panel</span>
      </div>
      <div className="px-2 py-4">
        <div className="space-y-1">
          <MenuItem
            to="/dashboard"
            icon={<svg className="w-5 h-5" /* Dashboard icon */ />}
            label="Dashboard"
            isActive={location.pathname === '/dashboard'}
          />
          <MenuItem
            icon={<svg className="w-5 h-5" /* Users icon */ />}
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
            icon={<svg className="w-5 h-5" /* Online icon */ />}
            label="Online User"
            isActive={location.pathname === '/online'}
          />
          <MenuItem
            to="/settings"
            icon={<svg className="w-5 h-5" /* Settings icon */ />}
            label="Settings"
            isActive={location.pathname === '/settings'}
          />
          <MenuItem
            to="/reports"
            icon={<svg className="w-5 h-5" /* Reports icon */ />}
            label="Reports"
            isActive={location.pathname === '/reports'}
          />
          <button
            onClick={handleLogout}
            className="w-full text-left flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg mx-2"
          >
            <svg className="w-5 h-5" /* Logout icon */ />
            <span className="ml-3">Logout</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
EOL
