/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Common interface for credentials to be passed around
 */
class AuthTokenCredentials {
    /**
     * @param {String} login The login value - ie. username, email, api-key
     * @param {String} secret The login secret - ie. password
     */
    constructor(login, secret) {
        this.login = login;
        this.secret = secret;
    }

    /**
     * Alias to this.login
     * @returns {String|*}
     */
    get username() {
        return this.login;
    }

    /**
     * Alias to this.secret
     * @returns {String|*}
     */
    get password() {
        return this.secret;
    }
}

module.exports = AuthTokenCredentials;