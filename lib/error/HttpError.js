/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const SecurityError = require('./SecurityError');

/**
 * The HttpError class used for all HTTP error types
 *
 * @Rest:Object
 */
class HttpError extends SecurityError {
    /**
     * @param {String} [msg] The error message
     * @param {Number} [status] The HTTP status to respond with
     * @param {Error} [previous] The previous error message
     */
    constructor(msg = 'HTTP Error', status = 500, previous = null) {
        super(msg, previous);
        this.status = status;
        this.headers = {};
    }

    /**
     * See if any custom headers have been set
     * @returns {boolean}
     */
    hasResponseHeaders() {
        return this.headers instanceof Object && Object.keys(this.headers).length !== 0;
    }

    /**
     * Get the response headers to send back (if any)
     * @returns {Object}
     */
    getResponseHeaders() {
        return this.headers;
    }

    /**
     * Add a response header to send back
     * @param {String} header The name of the header
     * @param {String} value The value of the header
     * @returns {void}
     */
    addResponseHeader(header, value) {
        this.headers[header.toLowerCase()] = value;
    }

    /**
     * Serialize this error
     *
     * @Rest:SerializeMethod
     *
     * @returns {Object}
     */
    toJSON() {
        return Object.assign({status: this.status}, super.toJSON());
    }
}

module.exports = HttpError;