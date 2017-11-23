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
     * Getter (shorthand access) for getAuthToken
     * @returns {AuthToken|null}
     */
    get token() {
        return this.getAuthToken();
    }

    /**
     * Getter (shorthand access) for getAuthCredentials
     * @returns {AuthTokenCredentials}
     */
    get credentials() {
        return this.getAuthCredentials();
    }

    /**
     * Getter (shorthand access) for getAuthResource
     * @returns {AuthResource|null}
     */
    get resource() {
        return this.getAuthResource();
    }

    /**
     * Getter (shorthand access) for getRealm
     * @returns {String|null}
     */
    get realm() {
        return this.getRealm();
    }

    /**
     * Getter (shorthand access) for isAuthenticated
     * @returns {Boolean}
     */
    get authenticated() {
        return this.isAuthenticated();
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
     * Get the auth credentials (username, password) from the token
     * @returns {AuthTokenCredentials|*}
     */
    getAuthCredentials() {
        return this._token && this._token.credentials;
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

    /**
     * Get the security realm we are authenticated for
     * @returns {String|null}
     */
    getRealm() {
        if (!this._token) {
            return null;
        }
        return this._token.realm;
    }

    /**
     * See if the auth token is fully authenticated
     * @returns {Boolean}
     */
    isAuthenticated() {
        if (!this._token) {
            return false;
        }
        return !!this._token.authenticated;
    }
}

module.exports = SecurityContext;