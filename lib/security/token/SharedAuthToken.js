/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthToken = require('./AuthToken');
const AuthTokenCredentials = require('./AuthTokenCredentials');
const AuthResource = require('./../resource/AuthResource');
const SharedAuthResource = require('./../resource/SharedAuthResource');

/**
 * The shared auth token is one that provides access to a realm on
 * behalf of another token created in a different realm
 */
class SharedAuthToken extends AuthToken {
    /**
     * {@inheritDoc}
     * @see AuthToken.getModulePath
     */
    static getModulePath() {
        return __filename;
    }

    /**
     * Deserialize a serialized AuthToken object into an AuthToken instance
     * @param {Object} serialized The serialized object
     * @returns {SharedAuthToken|*}
     */
    static deserialize(serialized) {
        if (serialized.resource && !(serialized.resource instanceof AuthResource)) {
            serialized.resource = new SharedAuthResource(serialized.resource);
        }
        return new this.prototype.constructor(
            serialized,
            serialized.realm,
            serialized.sharedFields || null,
            serialized.sharedRealm || null
        );
    }

    /**
     * Shared auth token
     * @param {AuthToken|Object} token The token to share
     * @param {String} realm The protected realm / firewall for this token (this realm)
     * @param {Object} [fields] hash of proxied resource fields (optional)
     * @param {String} [sharedRealm] the protected realm / firewall for the token being shared
     */
    constructor(token, realm, fields = null, sharedRealm = null) {
        let resource = token.resource;
        if (!(resource instanceof SharedAuthResource)) {
            resource = new SharedAuthResource(resource, fields);
        }
        super(
            resource,
            new AuthTokenCredentials(token.credentials && token.credentials.login, null),
            realm,
            token.roles,
            token.authenticated,
            token.stateless
        );
        this.__defineGetter__('shared', () => true);
        this.__defineGetter__('sharedRealm', () => sharedRealm || token.sharedRealm || token.realm);
        this.__defineGetter__('sharedFields', () => fields);
    }
}

module.exports = SharedAuthToken;