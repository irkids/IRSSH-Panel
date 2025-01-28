import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Users, Shield, Settings, Plus } from 'lucide-react';
import RoleModal from './RoleModal';

const RoleManagement = () => {
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Available permissions
  const permissions = [
    { id: 'users_view', name: 'View Users' },
    { id: 'users_create', name: 'Create Users' },
    { id: 'users_edit', name: 'Edit Users' },
    { id: 'users_delete', name: 'Delete Users' },
    { id: 'roles_view', name: 'View Roles' },
    { id: 'roles_manage', name: 'Manage Roles' },
    { id: 'protocols_view', name: 'View Protocols' },
    { id: 'protocols_manage', name: 'Manage Protocols' },
    { id: 'settings_view', name: 'View Settings' },
    { id: 'settings_manage', name: 'Manage Settings' },
  ];

  useEffect(() => {
    fetchRoles();
  }, []);

  const fetchRoles = async () => {
    try {
      const response = await fetch('/api/roles');
      const data = await response.json();
      setRoles(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching roles:', error);
      setLoading(false);
    }
  };

  const handleSaveRole = async (roleData) => {
    try {
      const method = selectedRole ? 'PUT' : 'POST';
      const url = selectedRole 
        ? `/api/roles/${selectedRole.id}` 
        : '/api/roles';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(roleData),
      });

      if (!response.ok) {
        throw new Error('Failed to save role');
      }

      await fetchRoles();
      setIsModalOpen(false);
      setSelectedRole(null);
    } catch (error) {
      console.error('Error saving role:', error);
    }
  };

  const handleDeleteRole = async (roleId) => {
    if (!window.confirm('Are you sure you want to delete this role?')) {
      return;
    }

    try {
      const response = await fetch(`/api/roles/${roleId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete role');
      }

      await fetchRoles();
    } catch (error) {
      console.error('Error deleting role:', error);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Role Management</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Role
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {roles.map((role) => (
            <div
              key={role.id}
              className="bg-white p-6 rounded-lg shadow hover:shadow-md transition-shadow"
            >
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold">{role.name}</h3>
                  <p className="text-gray-600 text-sm">{role.description}</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setSelectedRole(role);
                      setIsModalOpen(true);
                    }}
                    className="p-2 text-blue-600 hover:text-blue-800"
                  >
                    <Settings className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteRole(role.id)}
                    className="p-2 text-red-600 hover:text-red-800"
                  >
                    <Shield className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center text-sm text-gray-600">
                  <Users className="w-4 h-4 mr-2" />
                  <span>{role.restrictions.max_users || 'Unlimited'} users</span>
                </div>
                
                <div className="flex flex-wrap gap-1">
                  {role.permissions.map((permId) => {
                    const perm = permissions.find(p => p.id === permId);
                    return perm ? (
                      <span
                        key={permId}
                        className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded"
                      >
                        {perm.name}
                      </span>
                    ) : null;
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {isModalOpen && (
        <RoleModal
          role={selectedRole}
          permissions={permissions}
          onClose={() => {
            setIsModalOpen(false);
            setSelectedRole(null);
          }}
          onSave={handleSaveRole}
        />
      )}
    </div>
  );
};

export default RoleManagement;
