/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthToken = require('./../token/AuthToken');
const LogicError = require('./../../error/LogicError');
const AccessDeniedError = require('./../../error/AccessDeniedError');

/**
 * The abstract authenticator provides common logic and abstract methods for all authenticators
 * @abstract
 */
class AbstractAuthenticator {
    /**
     * Create an authentication token for the current request
     * @param {Object} request The conga request object
     * @param {String} [realm] The realm the token belongs to
     * @returns {Promise}
     * @abstract
     */
    createToken(request, realm = 'secure') {
        throw new LogicError('Your authenticator must implement the abstract method, "createToken".');
    }

    /**
     * See if an existing token is supported by this authenticator - you probably want to overwrite this
     * @param {AuthToken} token The authenticated token to check for
     * @param {String} realm The realm to check in
     * @returns {boolean}
     */
    supportsToken(token, realm) {
        return token instanceof AuthToken && token.realm === realm;
    }

    /**
     * Refresh a previously authenticated token - you probably want to overwrite this
     * @param {AuthToken} token The authenticated token to refresh
     * @param {AbstractProvider} provider The provider to use to refresh the token
     * @param {String} realm The realm we are refreshing the token for
     * @returns {Promise}
     */
    refreshToken(token, provider, realm) {
        return provider.refreshResource(token.resource).then(resource => {

            if (!provider.supportsResource(resource)) {
                return Promise.reject(new AccessDeniedError());
            }

            return Promise.resolve(new AuthToken(resource, token.credentials, realm, resource.roles || [], true));

        });
    }

    /**
     * Authenticate an auth token - you probably want to overwrite this
     * @param {AuthToken} token The auth token to authenticate
     * @param {AbstractProvider} provider The provider to use during authentication
     * @param {String} realm The realm to  authenticate in
     * @returns {Promise}
     */
    authenticateToken(token, provider, realm) {

        return provider.getResource(token.credentials).then(resource => {

            if (!provider.supportsResource(resource)) {
                return Promise.reject(new AccessDeniedError());
            }

            return Promise.resolve(new AuthToken(resource, token.credentials, realm, resource.roles || [], true));

        });
    }
}

module.exports = AbstractAuthenticator;
