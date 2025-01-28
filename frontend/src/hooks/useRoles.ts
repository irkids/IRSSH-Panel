// hooks/useRoles.ts

import { useState, useCallback } from 'react';
import type { Role, RoleFormData } from '../types/roles';

export const useRoles = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRoles = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/roles');
      if (!response.ok) {
        throw new Error('Failed to fetch roles');
      }
      const data = await response.json();
      setRoles(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, []);

  const createRole = useCallback(async (roleData: RoleFormData) => {
    try {
      setLoading(true);
      const response = await fetch('/api/roles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(roleData),
      });

      if (!response.ok) {
        throw new Error('Failed to create role');
      }

      await fetchRoles();
      setError(null);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create role');
      return false;
    } finally {
      setLoading(false);
    }
  }, [fetchRoles]);

  const updateRole = useCallback(async (id: string, roleData: RoleFormData) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/roles/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(roleData),
      });

      if (!response.ok) {
        throw new Error('Failed to update role');
      }

      await fetchRoles();
      setError(null);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
      return false;
    } finally {
      setLoading(false);
    }
  }, [fetchRoles]);

  const deleteRole = useCallback(async (id: string) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/roles/${id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete role');
      }

      await fetchRoles();
      setError(null);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete role');
      return false;
    } finally {
      setLoading(false);
    }
  }, [fetchRoles]);

  return {
    roles,
    loading,
    error,
    fetchRoles,
    createRole,
    updateRole,
    deleteRole,
  };
};
