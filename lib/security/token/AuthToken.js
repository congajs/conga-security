/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthResource = require('./../resource/AuthResource');
const AuthResourceProxy = require('./../resource/AuthResourceProxy');

/**
 * Authentication token used in the conga security protocol
 */
class AuthToken {
    /**
     * Get the module (absolute) path to this class
     * @returns {String}
     */
    static getModulePath() {
        return __filename;
    }

    /**
     * The filter method to use for JSON.stringify
     * @param {String} key The key being serialized
     * @param {*} value The value being serialized
     * @returns {*}
     */
    static serializeFilter(key, value) {
        if (key[0] === '_') {
            return undefined;
        }
        return value;
    }

    /**
     * Serialize an auth token (any type)
     * @param {AuthToken} token The token to serialize
     * @returns {String} The serialized package, including the module and serialized token object
     */
    static serialize(token) {
        return JSON.stringify({
            module: this.getModulePath(),
            token: JSON.parse(JSON.stringify(token, this.serializeFilter))
        });
    }

    /**
     * Deserialize a serialized AuthToken object into an AuthToken instance
     * @param {Object} serialized The serialized token object
     * @returns {AuthToken|*}
     */
    static deserialize(serialized) {
        if (serialized.resource && !(serialized.resource instanceof AuthResource)) {
            serialized.resource = new AuthResourceProxy(serialized.resource);
        }
        return new this.prototype.constructor(
            serialized.resource,
            serialized.credentials,
            serialized.realm || 'secure',
            serialized.roles || [],
            serialized.authenticated || false,
            serialized.stateless || false
        );
    }

    /**
     *
     * @param {String|AuthResource} resource The resource object we are authenticating with, or string (anon.)
     * @param {AuthTokenCredentials|*} credentials The secret password / api key, etc.
     * @param {String} [realm] The protected realm / firewall
     * @param {String|Array<String>} [roles] Array of roles are are authenticated with
     * @param {Boolean} [authenticated] Whether this token is authenticated
     * @param {Boolean} [stateless] Whether this auth-token has state or not (false if it has state) - state, here, means it is allowed to be saved in a session
     */
    constructor(
        resource,
        credentials,
        realm = 'secure',
        roles = [],
        authenticated = false,
        stateless = false
    ) {
        if (!Array.isArray(roles)) {
            roles = (roles && [roles]) || [];
        }
        roles = roles.map(role => role.toUpperCase());
        authenticated = authenticated && resource instanceof AuthResource;
        this.__defineGetter__('resource', () => resource);
        this.__defineGetter__('credentials', () => credentials);
        this.__defineGetter__('realm', () => realm);
        this.__defineGetter__('roles', () => roles.slice());
        this.__defineGetter__('authenticated', () => authenticated);
        this.__defineGetter__('stateless', () => stateless);
    }

    /**
     * See if this token has access to a role
     * @param {String|Array<String>} role The security role(s) being checked for
     * @returns {boolean}
     */
    hasRole(role) {
        if (role instanceof Array) {
            return role.every(r => this.hasRole(r));
        }
        return this.roles.indexOf(role.toUpperCase()) !== -1;
    }

    /**
     * Serialize this token
     * @returns {String}
     */
    serialize() {
        return this.constructor.serialize(this);
    }
}

module.exports = AuthToken;