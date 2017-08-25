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

/**
 * The anonymously authenticated token is an auth token that is not fully authenticated but
 * provides one time anonymous access.
 */
class AnonAuthToken extends AuthToken {
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
     * @returns {AuthToken|*}
     */
    static deserialize(serialized) {
        return new this.prototype.constructor(serialized.realm || 'secure');
    }

    /**
     * Anonymous, pre-authenticated token
     * @param {String} [realm] The protected realm / firewall
     */
    constructor(realm = 'secure') {
        super('anon.', new AuthTokenCredentials(null, null), realm, [], false, true);

        this.__defineGetter__('anonymous', () => true);
    }
}

module.exports = AnonAuthToken;