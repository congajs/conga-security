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
 * The ConfigurationError class is used for all errors related to security configuration
 *
 * @Rest:Object
 */
class ConfigurationError extends LogicError {
    /**
     * {@inheritDoc}
     */
    constructor(msg = 'Configuration Error', previous = null) {
        super(msg, previous);
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

module.exports = ConfigurationError;