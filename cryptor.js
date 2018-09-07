// Nodejs encryption with GCM
// Does not work with nodejs v0.10.31
// Part of https://github.com/chris-rock/node-crypto-examples

const crypto = require('crypto');

const algorithm = 'aes-128-gcm';
const aesKeyBitsLen = 128;
const aesKeyBytesLen = aesKeyBitsLen / 8;

const pbkdf2Salt = Buffer.from('4d3fe0d71d2abd2828e7a3196ea450d4', 'hex');
const pbkdf2Iterations = 1024;

const VERSION_BYTES = Buffer.from([0x01]);
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function deriveKey(password) {
  return crypto.pbkdf2Sync(password, pbkdf2Salt, pbkdf2Iterations, aesKeyBytesLen, 'sha256');
}

class Cryptor {
  /**
   * encrypts plaintext
   * @param  {string} password  the password to encrypt with
   * @param  {string} plaintext the plaintext to encrypt
   * @return {string} a hex encoded ciphertext
   */
  static encrypt(password, plaintext) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(password);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(Buffer.concat([VERSION_BYTES, iv]));
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex')
    ciphertext += cipher.final('hex');
    let tag = cipher.getAuthTag();

    return VERSION_BYTES.toString('hex') + iv.toString('hex') + ciphertext + tag.toString('hex');
  }

  /**
   * decrypts ciphertext
   * @param  {string} password   the password to decrypt the text with
   * @param  {string} ciphertext the hex encoded ciphertext
   * @return {string} the plaintext
   */
  static decrypt(password, ciphertext) {
    const ciphermsg = Buffer.from(ciphertext, 'hex');
    if (ciphermsg.length < VERSION_BYTES.length + IV_LENGTH + TAG_LENGTH) {
      throw new Error('ciphertext too short: ' + ciphermsg.length);
    }

    let pos = 0;
    for (; pos < VERSION_BYTES.length; pos++) {
      if (ciphermsg[pos] !== VERSION_BYTES[pos]) {
        throw new Error('version not valid: ' + ciphermsg[0]);
      }
    }

    const iv = ciphermsg.slice(pos, pos + IV_LENGTH);
    pos += iv.length;

    const cipherbytes = ciphermsg.slice(pos, ciphermsg.length - TAG_LENGTH);
    pos += cipherbytes.length;

    const tagbytes = ciphermsg.slice(pos);

    const key = deriveKey(password);

    let decipher = crypto.createDecipheriv(algorithm, key, iv)

    decipher.setAAD(Buffer.concat([VERSION_BYTES, iv]));
    decipher.setAuthTag(tagbytes);

    let dec = decipher.update(cipherbytes)
    dec += decipher.final('utf8');
    return dec;
  }
}

module.exports = Cryptor;