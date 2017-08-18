/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// core libs
const crypto = require('crypto');

// local libs
const AbstractEncryptor = require('./AbstractEncryptor');

/**
 * The default secret to use, if not provided
 * @type {string}
 */
const DEFAULT_SECRET = 'conga-hmac-encryptor';

/**
 * Crypto Hmac Encryptor
 */
class CryptoHmacEncryptor extends AbstractEncryptor {
    /**
     * @param {String} algo The encryption algorithm
     * @param {String} [digest] Digest parameter for crypto
     */
    constructor(algo, digest = 'hex') {
        super();
        this.algorithm = algo;
        this.digest = digest;
    }

    /**
     * Encrypt a string
     * @param {String} str The string to encrypt
     * @param {Object|*} [arg] The encryptor configuration or string secret
     * @returns {Promise} a promise that resolves a string
     */
    encrypt(str, arg = DEFAULT_SECRET) {
        let secret = arg;
        if (arg instanceof Object) {
            if (arg.fields instanceof Object && arg.fields.secret) {
                secret = arg.fields.secret;
            } else if (arg.secret) {
                secret = arg.secret;
            }
        }
        if (!secret) {
            secret = DEFAULT_SECRET;
        }
        return Promise.resolve(
            crypto.createHmac(this.algorithm, secret).update(str).digest(this.digest));
    }
}

module.exports = CryptoHmacEncryptor;