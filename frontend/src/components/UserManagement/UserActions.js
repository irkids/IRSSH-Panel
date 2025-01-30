import React from 'react';

const UserActions = ({ user, onEdit, onDelete, onRenew }) => {
  return (
    <div className="flex space-x-2">
      <button
        onClick={() => onEdit(user)}
        className="px-3 py-1 text-xs font-medium text-blue-600 hover:text-blue-700"
      >
        Edit
      </button>
      <button
        onClick={() => onRenew(user)}
        className="px-3 py-1 text-xs font-medium text-green-600 hover:text-green-700"
      >
        Renew
      </button>
      <button
        onClick={() => onDelete(user)}
        className="px-3 py-1 text-xs font-medium text-red-600 hover:text-red-700"
      >
        Delete
      </button>
    </div>
  );
};

export default UserActions;
