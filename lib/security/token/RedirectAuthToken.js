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

/**
 * The pre-authenticated token is an auth token that is not fully authenticated yet
 */
class RedirectAuthToken extends AuthToken {
    /**
     * {@inheritDoc}
     * @see AuthToken.getModulePath
     */
    static getModulePath() {
        return __filename;
    }

    /**
     * {@inheritDoc}
     * @see AuthToken.serialize
     */
    static serialize(token) {
        if (token.redirectModulePath !== this.getModulePath()) {
            return require(token.redirectModulePath).serialize(token);
        }
        return AuthToken.serialize(token);
    }

    /**
     * Deserialize a serialized AuthToken object into an AuthToken instance
     * @param {Object} serialized The serialized object
     * @returns {RedirectAuthToken|*}
     */
    static deserialize(serialized) {
        return new this.prototype.constructor(serialized, serialized.location);
    }

    /**
     * Anonymous, pre-authenticated token
     * @param {AuthToken} token The auth token we are redirecting for
     * @paran {String} location The location to redirect to
     */
    constructor(token, location) {
        super(
            token.resource,
            token.credentials,
            token.realm,
            token.roles,
            token.authenticated,
            token.stateless
        );
        this.__defineGetter__('_token', () => token);
        this.__defineGetter__('location', () => location);
        this.__defineGetter__('redirect', () => location);
        this.__defineGetter__('redirectModulePath', () => token.constructor.getModulePath())
    }

    /**
     * Get the source token (the auth token we are redirecting for)
     * @returns {AuthToken|*}
     */
    getSourceToken() {
        return this._token;
    }
}

module.exports = RedirectAuthToken;