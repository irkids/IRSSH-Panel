// store/roleStore.ts

import create from 'zustand';
import type { Role, RoleFormData } from '../types/roles';

interface RoleStore {
  roles: Role[];
  selectedRole: Role | null;
  loading: boolean;
  error: string | null;
  setRoles: (roles: Role[]) => void;
  setSelectedRole: (role: Role | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  fetchRoles: () => Promise<void>;
  createRole: (roleData: RoleFormData) => Promise<boolean>;
  updateRole: (id: string, roleData: RoleFormData) => Promise<boolean>;
  deleteRole: (id: string) => Promise<boolean>;
}

export const useRoleStore = create<RoleStore>((set, get) => ({
  roles: [],
  selectedRole: null,
  loading: false,
  error: null,
  
  setRoles: (roles) => set({ roles }),
  setSelectedRole: (role) => set({ selectedRole: role }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),

  fetchRoles: async () => {
    try {
      set({ loading: true, error: null });
      const response = await fetch('/api/roles');
      if (!response.ok) {
        throw new Error('Failed to fetch roles');
      }
      const roles = await response.json();
      set({ roles, loading: false });
    } catch (err) {
      set({ 
        error: err instanceof Error ? err.message : 'Failed to fetch roles',
        loading: false 
      });
    }
  },

  createRole: async (roleData) => {
    try {
      set({ loading: true, error: null });
      const response = await fetch('/api/roles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(roleData),
      });
      
      if (!response.ok) {
        throw new Error('Failed to create role');
      }
      
      await get().fetchRoles();
      return true;
    } catch (err) {
      set({ 
        error: err instanceof Error ? err.message : 'Failed to create role',
        loading: false 
      });
      return false;
    }
  },

  updateRole: async (id, roleData) => {
    try {
      set({ loading: true, error: null });
      const response = await fetch(`/api/roles/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(roleData),
      });
      
     if (!response.ok) {
        throw new Error('Failed to update role');
      }
      
      await get().fetchRoles();
      return true;
    } catch (err) {
      set({ 
        error: err instanceof Error ? err.message : 'Failed to update role',
        loading: false 
      });
      return false;
    }
  },

  deleteRole: async (id) => {
    try {
      set({ loading: true, error: null });
      const response = await fetch(`/api/roles/${id}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        throw new Error('Failed to delete role');
      }
      
      await get().fetchRoles();
      return true;
    } catch (err) {
      set({ 
        error: err instanceof Error ? err.message : 'Failed to delete role',
        loading: false 
      });
      return false;
    }
  },
}));
