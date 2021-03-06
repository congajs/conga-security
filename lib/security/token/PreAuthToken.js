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
class PreAuthToken extends AuthToken {
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
        return new this.prototype.constructor(
            serialized.credentials,
            serialized.realm || 'secure',
            serialized.stateless || false
        );
    }

    /**
     * Anonymous, pre-authenticated token
     * @param {AuthTokenCredentials|*} [credentials] The secret password / api key, etc.
     * @param {String} [realm] The protected realm / firewall
     * @param {Boolean} [stateless] Whether this auth-token has state or not (false if it has state) - state, here, means it is allowed to be saved in a session
     */
    constructor(credentials, realm = 'secure', stateless = false) {
        super('anon.', credentials, realm, [], false, stateless);
    }
}

module.exports = PreAuthToken;