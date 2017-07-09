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
 * The base security user class
 */
class AuthUser extends AuthResource {
    /**
     * @param {String} username
     * @param {String} password
     * @param {Array} [roles]
     */
    constructor(username, password, roles = []) {
        super(roles);
        this.username = username;
        this.password = password;
        this.salt = null;
    }

    /**
     * Get the salt
     * @returns {String|null}
     */
    getSalt() {
        return this.salt;
    }
}

module.exports = AuthUser;