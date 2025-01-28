// types/roles.ts

export interface TimeRestrictions {
  enabled: boolean;
  working_hours: {
    start: string;
    end: string;
  };
  working_days: string[];
}

export interface RoleRestrictions {
  max_users: number;
  ip_ranges: string[];
  time_restrictions: TimeRestrictions;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  restrictions: RoleRestrictions;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: string;
  name: string;
  description?: string;
  category?: string;
}

export interface RoleFormData {
  name: string;
  description: string;
  permissions: string[];
  restrictions: RoleRestrictions;
}
