const { redis } = require('../config/redis');
const config = require('../config/cache');

class Cache {
  constructor() {
    this.enabled = config.enabled;
    this.ttl = config.ttl;
    this.prefix = config.prefix || 'cache:';
  }

  async get(key) {
    if (!this.enabled) return null;

    try {
      const data = await redis.get(this.getKey(key));
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = this.ttl) {
    if (!this.enabled) return;

    try {
      await redis.set(
        this.getKey(key),
        JSON.stringify(value),
        'EX',
