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
const LogicError = require('./../../error/LogicError');

/**
 * The abstract provider class sets the interface for all providers and provides some functionality
 * @abstract
 */
class AbstractProvider {
    /**
     * @param {Object} [config] optional configuration object
     */
    constructor(config = null) {
        if (config) {
            this.setConfig(config);
        }
    }

    /**
     * Set the provider configuration on this instance
     * @param {Object} config
     * @returns {void}
     */
    setConfig(config) {
        this.config = config;
    }

    /**
     * See if this provider supports a given resource
     * @param {AuthResource|*} resource The resource to check for
     * @returns {boolean}
     * @abstract
     */
    supportsResource(resource) {
        throw new LogicError('Your custom provider must implement the abstract method, "supportsResource".');
    }

    /**
     * Get the resource that needs to be authenticated
     * @param {*} credentials The secret password / api key, etc.
     * @returns {Promise}
     * @abstract
     */
    getResource(credentials) {
        throw new LogicError('Your custom provider must implement the abstract method, "getResource".');
    }

    /**
     * Refresh an existing resource
     * @param {AuthResource|*} resource
     * @returns {Promise}
     * @abstract
     */
    refreshResource(resource) {
        throw new LogicError('Your custom provider must implement the abstract method, "refreshResource".');
    }

    /**
     * Verify a nonce encoded string with a secret - this might typically be used with a plain-text encryptor
     * @param {String} encoded The nonce-encoded string
     * @param {String} secret The secret used to md5 encode the nonce
     * @returns {boolean}
     */
    static verifyNonce(encoded, secret) {
        // encoded = encrypted_nonce
        // encrypted = md5(secret_nonce)
        // secret is the value stored in the storage engine as is plain text (be it encrypted or not)
        let [ encrypted, nonce ] = encoded.split('_');
        if (!nonce) {
            return false;
        }
        let check = crypto.createHmac('md5').update(secret + '_' + nonce).digest('hex');
        return check.length === encrypted.length &&
               crypto.timingSafeEqual(Buffer.from(check), Buffer.from(encrypted));
    }
}

module.exports = AbstractProvider;