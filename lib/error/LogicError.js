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
 * The LogicError class is used for all logic exceptions
 *
 * @Rest:Object
 */
class LogicError extends SecurityError {
    /**
     * {@inheritDoc}
     */
    constructor(msg = 'Logic Error', previous = null) {
        super(msg, previous);
    }

    /**
     * {@inheritDoc}
     *
     * @Rest:SerializeMethod
     */
    toJSON() {
        return super.toJSON();
    }
}

module.exports = LogicError;