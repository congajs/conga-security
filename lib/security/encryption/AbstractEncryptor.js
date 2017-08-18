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

/**
 * The abstract encryptor defines a common interface
 * @abstract
 */
class AbstractEncryptor {
    /**
     * Encrypt a string
     * @param {String} str The string to encrypt
     * @param {Object|*} [config] The encryptor configuration argument
     * @returns {Promise} a promise that resolves a string
     * @abstract
     */
    encrypt(str, config = {}) {
        throw new LogicError('Your encryptor must implement the abstract method, "encrypt".');
    }

    /**
     * Compare a plain text string to an encrypted string to see if they are the same
     * @param {String} str The string to encrypt
     * @param {String} encrypted The encrypted string
     * @param {Object|*} [config] The encryptor configuration argument
     * @returns {Promise} a promise that resolves a boolean
     */
    compare(str, encrypted, config = {}) {
        return this.encrypt(str, config).then(check => {
            return Promise.resolve(
               check.length === encrypted.length &&
               crypto.timingSafeEqual(Buffer.from(check), Buffer.from(encrypted))
            );
        });
    }
}

module.exports = AbstractEncryptor;
