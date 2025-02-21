const crypto = require('crypto');
const config = require('../config/security');

class Encryption {
  constructor() {
    this.algorithm = config.encryption.algorithm;
    this.ivLength = config.encryption.ivLength;
    this.saltLength = config.encryption.saltLength;
    this.tagLength = config.encryption.tagLength;
    this.keyLength = config.encryption.keyLength;
    this.iterations = config.encryption.iterations;
  }

  async encrypt(text, key) {
    const salt = crypto.randomBytes(this.saltLength);
    const iv = crypto.randomBytes(this.ivLength);
    
    const derivedKey = await this.deriveKey(key, salt);
    const cipher = crypto.createCipheriv(this.algorithm, derivedKey, iv, {
      authTagLength: this.tagLength
    });

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  async decrypt(encryptedData, key) {
    const { encrypted, iv, salt, authTag } = encryptedData;
    
    const derivedKey = await this.deriveKey(key, Buffer.from(salt, 'hex'));
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      derivedKey,
      Buffer.from(iv, 'hex'),
      { authTagLength: this.tagLength }
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  async deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        this.iterations,
        this.keyLength,
        'sha512',
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });
  }

  generateRandomKey(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  hash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  hmac(data, key) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }
}

module.exports = new Encryption();
