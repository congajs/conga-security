/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const LogicError = require('./LogicError');

/**
 * The InvalidArgumentError class is used for all invalid argument exceptions
 *
 * @Rest:Object
 */
class InvalidArgumentError extends LogicError {
    /**
     * {@inheritDoc}
     */
    constructor(msg = 'Invalid Argument', previous = null) {
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

module.exports = InvalidArgumentError;