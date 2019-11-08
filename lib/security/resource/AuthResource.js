/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * An authenticated resource (user, api client, etc)
 */
class AuthResource {
    /**
     *
     * @param {Array} [roles]
     */
    constructor(roles = []) {
        // make sure we have an array
        if (!(roles instanceof Array)) {
            roles = (roles && [roles]) || [];
        }
        this.roles = roles;
    }

    /**
     * See if this user has an access role
     * @param {String|Array<String>} role The security role(s) being checked for
     * @returns {boolean}
     */
    hasRole(role) {
        if (role instanceof Array) {
            return role.every(r => this.hasRole(r));
        }
        return this.roles.indexOf(role) !== -1;
    }
}

module.exports = AuthResource;