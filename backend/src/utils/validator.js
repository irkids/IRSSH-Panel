const { z } = require('zod');

const validators = {
  user: z.object({
    username: z.string()
      .min(3, 'Username must be at least 3 characters')
      .max(50, 'Username cannot exceed 50 characters')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores and hyphens'),
    email: z.string()
      .email('Invalid email address'),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    role: z.enum(['admin', 'user']).optional()
  }),

  protocol: z.object({
    name: z.string()
      .min(3, 'Name must be at least 3 characters')
      .max(100, 'Name cannot exceed 100 characters'),
    type: z.enum(['SSH', 'L2TP', 'IKEv2', 'CISCO', 'WIREGUARD', 'SINGBOX']),
    config: z.object({
      port: z.number()
        .int('Port must be an integer')
        .min(1, 'Port must be greater than 0')
        .max(65535, 'Port cannot exceed 65535'),
      maxConnections: z.number()
        .int('Max connections must be an integer')
        .min(1, 'Max connections must be greater than 0'),
      timeout: z.number()
        .int('Timeout must be an integer')
        .min(0, 'Timeout cannot be negative')
    }).strict(),
    enabled: z.boolean().optional()
  }),

  setting: z.object({
    key: z.string()
      .min(1, 'Key is required')
      .max(100, 'Key cannot exceed 100 characters'),
    value: z.any(),
    description: z.string().optional()
  }),

  metric: z.object({
    name: z.string()
      .min(1, 'Name is required')
      .max(100, 'Name cannot exceed 100 characters'),
    value: z.number(),
    type: z.enum(['gauge', 'counter', 'histogram']),
    labels: z.record(z.string()).optional()
  })
};

class Validator {
  static validate(schema, data) {
    try {
      const validationSchema = validators[schema];
      if (!validationSchema) {
        throw new Error(`Unknown validation schema: ${schema}`);
      }

      const result = validationSchema.safeParse(data);

      if (!result.success) {
        return {
          success: false,
          errors: result.error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message
          }))
        };
      }

      return {
        success: true,
        data: result.data
      };
    } catch (error) {
      return {
        success: false,
        errors: [{ message: error.message }]
      };
    }
  }

  static validatePartial(schema, data) {
    try {
      const validationSchema = validators[schema];
      if (!validationSchema) {
        throw new Error(`Unknown validation schema: ${schema}`);
      }

      const partialSchema = validationSchema.partial();
      const result = partialSchema.safeParse(data);

      if (!result.success) {
        return {
          success: false,
          errors: result.error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message
          }))
        };
      }

      return {
        success: true,
        data: result.data
      };
    } catch (error) {
      return {
        success: false,
        errors: [{ message: error.message }]
      };
    }
  }
}

module.exports = Validator;
