const { z } = require('zod');

const userSchema = z.object({
  username: z.string().min(3).max(50),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(['admin', 'user']).optional()
});

const protocolSchema = z.object({
  name: z.string().min(3).max(100),
  type: z.enum(['SSH', 'L2TP', 'IKEv2', 'CISCO', 'WIREGUARD', 'SINGBOX']),
  config: z.object({
    port: z.number(),
    maxConnections: z.number(),
    encryption: z.string(),
    settings: z.record(z.any())
  }).strict(),
  enabled: z.boolean().optional()
});

const validate = (schema) => (data) => {
  try {
    return {
      success: true,
      data: schema.parse(data)
    };
  } catch (error) {
    return {
      success: false,
      errors: error.errors
    };
  }
};

module.exports = {
  validateUser: validate(userSchema),
  validateProtocol: validate(protocolSchema)
};
