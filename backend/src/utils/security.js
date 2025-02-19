const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');

class SecurityService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.secretKey = config.security.secretKey;
    this.jwtSecret = config.security.jwtSecret;
  }

  encrypt(text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.secretKey, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encrypted, iv, authTag) {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.secretKey,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  generateToken(user) {
    return jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role
      },
      this.jwtSecret,
      { expiresIn: '24h' }
    );
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(
      password,
      salt,
      10000,
      64,
      'sha512'
    ).toString('hex');
    
    return { hash, salt };
  }

  verifyPassword(password, hash, salt) {
    const verifyHash = crypto.pbkdf2Sync(
      password,
      salt,
      10000,
      64,
      'sha512'
    ).toString('hex');
    
    return hash === verifyHash;
  }

  generateSecureKey(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

module.exports = new SecurityService();
