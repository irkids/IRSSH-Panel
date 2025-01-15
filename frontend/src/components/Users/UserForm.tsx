// src/components/Users/UserForm.tsx
import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'react-hot-toast';

const userSchema = z.object({
  username: z.string().min(3).max(50),
  email: z.string().email().optional().nullable(),
  protocol: z.enum(['ssh', 'l2tp', 'ikev2', 'cisco', 'wireguard', 'shadowsocks', 'tuic', 'vless', 'hysteria2']),
  password: z.string().min(8).optional(),
  dataLimit: z.number().optional(),
  validUntil: z.string().optional(),
  status: z.enum(['active', 'disabled', 'expired']).default('active'),
  notes: z.string().optional()
});

type UserFormData = z.infer<typeof userSchema>;

interface Props {
  onSubmit: (data: UserFormData) => void;
  initialData?: Partial<UserFormData>;
  onCancel: () => void;
  isLoading?: boolean;
}

const UserForm = ({ onSubmit, initialData, onCancel, isLoading }: Props) => {
  const { register, handleSubmit, formState: { errors } } = useForm<UserFormData>({
    resolver: zodResolver(userSchema),
    defaultValues: initialData
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {/* Username */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Username
          {errors.username && (
            <span className="ml-2 text-xs text-red-500">
              {errors.username.message}
            </span>
          )}
        </label>
        <input
          type="text"
          {...register('username')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        />
      </div>

      {/* Protocol */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Protocol
          {errors.protocol && (
            <span className="ml-2 text-xs text-red-500">
              {errors.protocol.message}
            </span>
          )}
        </label>
        <select
          {...register('protocol')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        >
          <option value="ssh">SSH</option>
          <option value="l2tp">L2TP</option>
          <option value="ikev2">IKEv2</option>
          <option value="cisco">Cisco AnyConnect</option>
          <option value="wireguard">WireGuard</option>
          <option value="shadowsocks">Shadowsocks</option>
          <option value="tuic">TUIC</option>
          <option value="vless">VLess</option>
          <option value="hysteria2">Hysteria2</option>
        </select>
      </div>

      {/* Password */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Password
          {errors.password && (
            <span className="ml-2 text-xs text-red-500">
              {errors.password.message}
            </span>
          )}
        </label>
        <input
          type="password"
          {...register('password')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          placeholder={initialData ? 'Leave blank to keep current password' : ''}
        />
      </div>

      {/* Email */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Email (Optional)
          {errors.email && (
            <span className="ml-2 text-xs text-red-500">
              {errors.email.message}
            </span>
          )}
        </label>
        <input
          type="email"
          {...register('email')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        />
      </div>

      {/* Data Limit */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Data Limit (GB)
          {errors.dataLimit && (
            <span className="ml-2 text-xs text-red-500">
              {errors.dataLimit.message}
            </span>
          )}
        </label>
        <input
          type="number"
          {...register('dataLimit', { valueAsNumber: true })}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        />
      </div>

      {/* Valid Until */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Valid Until
          {errors.validUntil && (
            <span className="ml-2 text-xs text-red-500">
              {errors.validUntil.message}
            </span>
          )}
        </label>
        <input
          type="date"
          {...register('validUntil')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        />
      </div>

      {/* Status */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Status
          {errors.status && (
            <span className="ml-2 text-xs text-red-500">
              {errors.status.message}
            </span>
          )}
        </label>
        <select
          {...register('status')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
        >
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="expired">Expired</option>
        </select>
      </div>

      {/* Notes */}
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Notes
          {errors.notes && (
            <span className="ml-2 text-xs text-red-500">
              {errors.notes.message}
            </span>
          )}
        </label>
        <textarea
          {...register('notes')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          rows={3}
        />
      </div>

      {/* Form Actions */}
      <div className="flex justify-end space-x-3">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-gray-700 hover:text-gray-900"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {isLoading ? 'Saving...' : initialData ? 'Update User' : 'Create User'}
        </button>
      </div>
    </form>
  );
};

export default UserForm;
