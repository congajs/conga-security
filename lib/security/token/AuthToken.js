/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthResource = require('./../AuthResource');

/**
 * Authentication token used in the conga security protocol
 */
class AuthToken {
    /**
     *
     * @param {String|AuthResource} resource The resource object we are authenticating with, or string (anon.)
     * @param {AuthTokenCredentials|*} credentials The secret password / api key, etc.
     * @param {String} [realm] The protected realm / firewall
     * @param {String|Array<String>} [roles] Array of roles are are authenticated with
     * @param {Boolean} [authenticated] Whether this token is authenticated
     * @param {Boolean} [stateless] Whether this auth-token has state or not (false if it has state) - state, here, means it is allowed to be saved in a session
     */
    constructor(resource, credentials, realm = 'secure', roles = [], authenticated = false, stateless = false) {

        if (!(roles instanceof Array)) {
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
}

module.exports = AuthToken;