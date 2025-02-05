// src/stores/roleStore.ts
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// Types
export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  createdAt: Date;
  lastLogin?: Date;
  status: UserStatus;
  protocol: Protocol;
  trafficLimit?: number;
  usedTraffic?: number;
  expiryDate?: Date;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  RESELLER = 'reseller'
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  EXPIRED = 'expired',
  SUSPENDED = 'suspended'
}

export enum Protocol {
  SSH = 'ssh',
  L2TP = 'l2tp',
  IKEV2 = 'ikev2',
  CISCO = 'cisco',
  WIREGUARD = 'wireguard',
  SINGBOX = 'singbox'
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  roles: {
    [UserRole.ADMIN]: string[];
    [UserRole.USER]: string[];
    [UserRole.RESELLER]: string[];
  };
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  logout: () => void;
  hasPermission: (permission: string) => boolean;
  updateUserRole: (userId: string, role: UserRole) => void;
}

const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      roles: {
        [UserRole.ADMIN]: ['all'],
        [UserRole.USER]: ['view_own_stats', 'change_own_password'],
        [UserRole.RESELLER]: ['create_user', 'view_users', 'edit_users', 'delete_users']
      },

      setUser: (user) => set({ 
        user, 
        isAuthenticated: !!user 
      }),

      setToken: (token) => set({ token }),

      logout: () => set({ 
        user: null, 
        token: null, 
        isAuthenticated: false 
      }),

      hasPermission: (permission: string) => {
        const { user, roles } = get();
        if (!user) return false;
        
        const userRole = user.role;
        if (userRole === UserRole.ADMIN) return true;
        
        const allowedPermissions = roles[userRole] || [];
        return allowedPermissions.includes(permission);
      },

      updateUserRole: async (userId: string, role: UserRole) => {
        try {
          // API call to update user role
          const response = await fetch(`/api/users/${userId}/role`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${get().token}`
            },
            body: JSON.stringify({ role })
          });

          if (!response.ok) {
            throw new Error('Failed to update user role');
          }

          const updatedUser = await response.json();
          
          // Update local state if the updated user is the current user
          if (get().user?.id === userId) {
            set({ user: updatedUser });
          }
          
        } catch (error) {
          console.error('Error updating user role:', error);
          throw error;
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        token: state.token,
        user: state.user
      })
    }
  )
);

export default useAuthStore;
