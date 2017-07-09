/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const HttpError = require('./HttpError');

/**
 * Error class for all access denied errors
 *
 * @Rest:Object
 */
class AccessDeniedError extends HttpError {
    /**
     * {@inheritDoc}
     */
    constructor(msg = 'Access Denied', status = 403, previous = null) {
        super(msg, status, previous);
    }

    /**
     * {@inheritdoc}
     *
     * @Rest:SerializeMethod
     */
    toJSON() {
        return super.toJSON();
    }
}

module.exports = AccessDeniedError;