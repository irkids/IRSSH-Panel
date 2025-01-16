// src/hooks/api/index.ts
import { useQuery, useMutation, useQueryClient } from 'react-query';
import axios from '@/lib/axios';
import { toast } from 'react-hot-toast';

// Users
export const useUsers = (params?: any) => {
  return useQuery(['users', params], async () => {
    const { data } = await axios.get('/users', { params });
    return data;
  });
};

export const useUser = (id: string) => {
  return useQuery(['users', id], async () => {
    const { data } = await axios.get(`/users/${id}`);
    return data;
  });
};

export const useCreateUser = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async (userData: any) => {
      const { data } = await axios.post('/users', userData);
      return data;
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('users');
        toast.success('User created successfully');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to create user');
      },
    }
  );
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async ({ id, userData }: { id: string; userData: any }) => {
      const { data } = await axios.put(`/users/${id}`, userData);
      return data;
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('users');
        toast.success('User updated successfully');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to update user');
      },
    }
  );
};

export const useDeleteUser = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async (id: string) => {
      await axios.delete(`/users/${id}`);
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('users');
        toast.success('User deleted successfully');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to delete user');
      },
    }
  );
};

// Protocols
export const useProtocols = () => {
  return useQuery('protocols', async () => {
    const { data } = await axios.get('/protocols');
    return data;
  });
};

export const useProtocolConfig = (protocol: string) => {
  return useQuery(['protocols', protocol], async () => {
    const { data } = await axios.get(`/protocols/${protocol}`);
    return data;
  });
};

export const useUpdateProtocolConfig = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async ({ protocol, config }: { protocol: string; config: any }) => {
      const { data } = await axios.put(`/protocols/${protocol}`, config);
      return data;
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('protocols');
        toast.success('Protocol configuration updated');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to update protocol configuration');
      },
    }
  );
};

// System Monitoring
export const useSystemMetrics = () => {
  return useQuery(
    'systemMetrics',
    async () => {
      const { data } = await axios.get('/monitoring/metrics');
      return data;
    },
    {
      refetchInterval: 5000, // Refetch every 5 seconds
    }
  );
};

export const useResourceUsage = (resource: string, period: string = '24h') => {
  return useQuery(['resourceUsage', resource, period], async () => {
    const { data } = await axios.get(`/monitoring/resources/${resource}`, {
      params: { period },
    });
    return data;
  });
};

export const useNetworkStats = (period: string = '24h') => {
  return useQuery(['networkStats', period], async () => {
    const { data } = await axios.get('/monitoring/network', {
      params: { period },
    });
    return data;
  });
};

// Settings
export const useSystemSettings = () => {
  return useQuery('systemSettings', async () => {
    const { data } = await axios.get('/settings/system');
    return data;
  });
};

export const useUpdateSystemSettings = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async (settings: any) => {
      const { data } = await axios.post('/settings/system', settings);
      return data;
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('systemSettings');
        toast.success('Settings updated successfully');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to update settings');
      },
    }
  );
};

// Backups
export const useBackups = () => {
  return useQuery('backups', async () => {
    const { data } = await axios.get('/settings/backups');
    return data;
  });
};

export const useCreateBackup = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async (config: any) => {
      const { data } = await axios.post('/settings/backup', config);
      return data;
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('backups');
        toast.success('Backup created successfully');
      },
      onError: (error: any) => {
        toast.error(error.response?.data?.message || 'Failed to create backup');
      },
    }
  );
};

// Online Users
export const useOnlineUsers = () => {
  return useQuery(
    'onlineUsers',
    async () => {
      const { data } = await axios.get('/users/online');
      return data;
    },
    {
      refetchInterval: 10000, // Refetch every 10 seconds
    }
  );
};
