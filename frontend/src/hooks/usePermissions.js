import { useCallback } from 'react';
import { useAuth } from './useAuth';

const permissionMap = {
  admin: ['*'],
  user: [
    'read:protocols',
    'write:protocols',
    'read:metrics',
    'read:profile',
    'write:profile'
  ],
  guest: ['read:public']
};

export const usePermissions = () => {
  const { user } = useAuth();

  const hasPermission = useCallback((permission) => {
    if (!user) return false;

    const userPermissions = permissionMap[user.role] || [];
    return userPermissions.includes('*') || userPermissions.includes(permission);
  }, [user]);

  const hasAnyPermission = useCallback((permissions) => {
    return permissions.some(permission => hasPermission(permission));
  }, [hasPermission]);

  const hasAllPermissions = useCallback((permissions) => {
    return permissions.every(permission => hasPermission(permission));
  }, [hasPermission]);

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions
  };
};
