/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const LogicError = require('./../../error/LogicError');

/**
 * The abstract provider config class is used to register custom built-in providers
 * @abstract
 */
class AbstractProviderConfig {
    /**
     * Check to see if this provider supports a specific config object
     *
     * @param {Object} config The configuration object
     * @returns {Boolean}
     * @abstract
     */
    supportsConfig(config) {
        throw new LogicError('Your provider config must implement the abstract method, "supportsConfig".')
    }

    /**
     * Instantiate / return an instance of this provider type, using the given configuration object
     *
     * @param {Object} config The configuration object
     * @returns {AbstractProvider}
     * @abstract
     */
    useConfig(config) {
        throw new LogicError('Your provider config must implement the abstract method, "useConfig".')
    }
}

module.exports = AbstractProviderConfig;