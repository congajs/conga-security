/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * The all errors from this bundle inherit from this class
 *
 * @Rest:Object
 */
class SecurityError extends Error {
    /**
     * @param {String} [msg] The error message
     * @param {Error} [previous] The previous error message
     */
    constructor(msg = 'Security Error', previous = null) {
        super(msg);
        this.previous = null;
        if (previous instanceof Error) {
            this.previous = previous;
            this.stack += '\n' + previous.stack;
        }
    }

    /**
     * Set the auth-token for the error
     * @param {AuthToken} token
     * @returns {void}
     */
    setAuthToken(token) {
        this._token = token;
    }

    /**
     * Get the auth-token for the error
     * @returns {AuthToken|*}
     */
    getAuthToken() {
        return this._token;
    }

    /**
     * Serialize this error
     *
     * @Rest:SerializeMethod
     *
     * @returns {Object}
     */
    toJSON() {
        let obj = { message : this.message };
        if (this.previous) {
            if (this.previous.toJSON instanceof Function) {
                let previousObj = this.previous.toJSON() || {};
                previousObj.previousMessage = previousObj.message;
                obj = Object.assign({}, previousObj, obj);
            }
        }
        return obj;
    }
}

module.exports = SecurityError;