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
          ttl
        );
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  async delete(key) {
    if (!this.enabled) return;

    try {
      await redis.del(this.getKey(key));
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  }

  async clear() {
    if (!this.enabled) return;

    try {
      const keys = await redis.keys(`${this.prefix}*`);
      if (keys.length > 0) {
        await redis.del(keys);
      }
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }

  async remember(key, ttl, callback) {
    if (!this.enabled) {
      return callback();
    }

    try {
      const cachedValue = await this.get(key);
      if (cachedValue !== null) {
        return cachedValue;
      }

      const freshValue = await callback();
      await this.set(key, freshValue, ttl);
      return freshValue;
    } catch (error) {
      console.error('Cache remember error:', error);
      return callback();
    }
  }

  async tags(tags) {
    return new TaggedCache(this, Array.isArray(tags) ? tags : [tags]);
  }

  getKey(key) {
    return `${this.prefix}${key}`;
  }
}

class TaggedCache {
  constructor(cache, tags) {
    this.cache = cache;
    this.tags = tags;
  }

  async get(key) {
    const tagVersions = await this.getTagVersions();
    if (tagVersions === null) return null;

    const value = await this.cache.get(this.getTaggedKey(key, tagVersions));
    return value;
  }

  async set(key, value, ttl = null) {
    const tagVersions = await this.getTagVersions();
    await this.cache.set(
      this.getTaggedKey(key, tagVersions),
      value,
      ttl
    );
  }

  async flush() {
    await Promise.all(
      this.tags.map(tag => 
        this.cache.increment(`tag:${tag}:version`)
      )
    );
  }

  async getTagVersions() {
    const versions = await Promise.all(
      this.tags.map(tag =>
        this.cache.get(`tag:${tag}:version`)
      )
    );

    if (versions.includes(null)) {
      return null;
    }

    return versions;
  }

  getTaggedKey(key, versions) {
    return `${this.tags.join('|')}:${versions.join('|')}:${key}`;
  }
}

module.exports = new Cache();
