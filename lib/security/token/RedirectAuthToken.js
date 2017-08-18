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
     * Anonymous, pre-authenticated token
     * @param {AuthToken} token The auth token you are redirecting for
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
        this.__defineGetter__('location', () => location);
    }
}

module.exports = RedirectAuthToken;