/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const InvalidArgumentError = require('./../error/InvalidArgumentError');
const AuthToken = require('./token/AuthToken');

/**
 * The SecurityContext holds on to the authentication token for a single request
 */
class SecurityContext {
    /**
     * Initialize the security context properties
     */
    constructor() {
        /**
         * @type {AuthToken}
         * @private
         */
        this._token = null;
    }

    /**
     * Set the auth token
     * @param {AuthToken} token The security auth token resolved from the firewall
     * @returns {void}
     * @throws InvalidArgumentError for not providing an instance of AuthToken
     */
    setAuthToken(token) {
        if (!(token instanceof AuthToken)) {
            throw new InvalidArgumentError(
                'Security auth token is expecting an instance of conga-security:security/token/AuthToken');
        }
        this._token = token;
    }

    /**
     * Get the auth token
     * @returns {AuthToken|null}
     */
    getAuthToken() {
        return this._token;
    }

    /**
     * Get the security auth resource
     * @returns {AuthResource|null}
     */
    getAuthResource() {
        if (!this._token) {
            return null;
        }
        return this._token.resource;
    }
}

module.exports = SecurityContext;