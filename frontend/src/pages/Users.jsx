import React, { useState, useEffect } from 'react';
import { userService } from '../services/users';
import { Table, Button, Alert, Card } from '../components/common';
import { Users as UsersIcon, Edit, Trash2 } from 'lucide-react';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const data = await userService.getUsers();
      setUsers(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await userService.deleteUser(id);
      setUsers(users.filter(user => user.id !== id));
    } catch (err) {
      setError(err.message);
    }
  };

  const columns = [
    {
      title: 'Username',
      key: 'username'
    },
    {
      title: 'Email',
      key: 'email'
    },
    {
      title: 'Role',
      key: 'role',
      render: (user) => (
        <span className={`px-2 py-1 rounded-full text-sm ${
          user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
        }`}>
          {user.role}
        </span>
      )
    },
    {
      title: 'Status',
      key: 'status',
      render: (user) => (
        <span className={`px-2 py-1 rounded-full text-sm ${
          user.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
        }`}>
          {user.status}
        </span>
      )
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (user) => (
        <div className="flex space-x-2">
          <Button
            variant="light"
            size="sm"
            icon={<Edit className="w-4 h-4" />}
            onClick={() => {/* Handle edit */}}
          >
            Edit
          </Button>
          <Button
            variant="danger"
            size="sm"
            icon={<Trash2 className="w-4 h-4" />}
            onClick={() => handleDelete(user.id)}
          >
            Delete
          </Button>
        </div>
      )
    }
  ];

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold flex items-center">
          <UsersIcon className="w-6 h-6 mr-2" />
          Users
        </h1>
        <Button
          variant="primary"
          onClick={() => {/* Handle create */}}
        >
          Add User
        </Button>
      </div>

      {error && (
        <Alert
          variant="error"
          message={error}
          className="mb-4"
          onClose={() => setError(null)}
        />
      )}

      <Card>
        <Table
          columns={columns}
          data={users}
          loading={loading}
          emptyMessage="No users found"
        />
      </Card>
    </div>
  );
};

export default Users;
