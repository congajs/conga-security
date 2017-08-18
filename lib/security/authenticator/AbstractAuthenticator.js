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
const AuthToken = require('./../token/AuthToken');
const LogicError = require('./../../error/LogicError');
const AccessDeniedError = require('./../../error/AccessDeniedError');

/**
 * The abstract authenticator provides common logic and abstract methods for all authenticators
 * @abstract
 */
class AbstractAuthenticator {

    /**
     *
     * @param {Object} options Configuration options
     */
    constructor(options = {}) {
        this.setOptions(options);
    }

    /**
     * Support the factory method for custom options
     * @param options
     * @returns {AbstractAuthenticator}
     */
    useConfig(options = {}) {
        return new this.constructor(options);
    }

    /**
     * Set the configuration options
     * @param {Object} options The configuration options
     * @returns {void}
     */
    setOptions(options = {}) {
        this.options = options || {};
    }

    /**
     * See if this route is an anonymous route for this authenticator
     * @param {Object} request The conga request object
     * @returns {boolean}
     */
    isAnonymousRoute(request) {
        // if it's the redirect route, allow anonymous access
        return this.options.redirect &&
            request.originalUrl.length === this.options.redirect.length &&
            crypto.timingSafeEqual(Buffer.from(request.originalUrl),
                                   Buffer.from(this.options.redirect));
    }

    /**
     * See if the request should redirect after authentication
     * @param {Object} request The conga request object
     * @param {AuthToken} token The resolved auth token for this request (if any)
     * @returns {boolean}
     */
    shouldRedirect(request, token) {
        return false;
    }

    /**
     * Create an authentication token for the current request
     * @param {Object} request The conga request object
     * @param {String} [realm] The realm the token belongs to
     * @returns {Promise}
     * @abstract
     */
    createToken(request, realm = 'secure') {
        throw new LogicError(
            'Your authenticator must implement the abstract method, "createToken".');
    }

    /**
     * See if an existing token is supported by this authenticator - you probably want to overwrite this
     * @param {AuthToken} token The authenticated token to check for
     * @param {String} realm The realm to check in
     * @returns {boolean}
     */
    supportsToken(token, realm) {
        // NOTE: when a token is decrypted, it's returned as AuthToken, despite its original class
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
                return Promise.reject(this.getAccessDeniedError());
            }

            return Promise.resolve(new AuthToken(
                resource,
                token.credentials,
                realm,
                resource.roles || [],
                true,
                token.stateless
            ));
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
                return Promise.reject(this.getAccessDeniedError());
            }

            return Promise.resolve(new AuthToken(
                resource,
                token.credentials,
                realm,
                resource.roles || [],
                true,
                token.stateless
            ));
        });
    }

    /**
     * Get an access denied error that supports the redirect option
     * @param {String} [msg] The error message
     * @param {Number} [status] The HTTP status to respond with
     * @returns {AccessDeniedError|HttpRedirectError}
     */
    getAccessDeniedError(msg = 'Access Denied', status = 403) {
        const err = new AccessDeniedError(msg, status);
        if (this.options.redirect) {
            err.status = 302;
            err.addResponseHeader('Location', this.options.redirect);
        }
        return err;
    }
}

module.exports = AbstractAuthenticator;
