/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractProviderConfig = require('./../security/provider/AbstractProviderConfig');
const ChainProvider = require('./../security/provider/ChainProvider');
const InMemoryProvider = require('./../security/provider/InMemoryProvider');
const BassProvider = require('./../security/provider/BassProvider');
const InvalidArgumentError = require('./../error/InvalidArgumentError');

/**
 * See if a configuration object is for a chain provider
 * @param {Object} config
 * @returns {boolean}
 */
const isChainConfig = config => config instanceof Array;

/**
 * See if a configuration object is for an in-memory provider
 * @param {Object} config
 * @returns {boolean}
 */
const isMemoryConfig = config => config instanceof Object &&
                                 config.memory instanceof Object &&
                                 config.memory.users instanceof Object;

/**
 * See if a configuration object is for a bass provider
 * @param {Object} config
 * @returns {boolean}
 */
const isBassConfig = config => config instanceof Object &&
                               config.bass instanceof Object &&
                               config.bass.document !== undefined &&
                               config.bass.login !== undefined &&
                               config.bass.secret !== undefined;

/**
 * The provider config service is used to implement and support core bundle providers for conga-security
 */
class ProviderConfigService extends AbstractProviderConfig {
    /**
     * {@inheritDoc}
     * @see AbstractProviderConfig.constructor
     */
    constructor(container) {
        super();
        this.container = container;
    }

    /**
     * {@inheritDoc}
     * @see AbstractProviderConfig.supportsConfig
     */
    supportsConfig(config) {
        return isChainConfig(config) ||
               isMemoryConfig(config) ||
               isBassConfig(config);
    }

    /**
     * {@inheritDoc}
     * @see AbstractProviderConfig.useConfig
     * @throws InvalidArgumentError when a configuration object is given that is not supported
     */
    useConfig(config) {

        // UNSURE: should we cache the provider to config with a config JSON hash?  memory vs performance?

        if (isChainConfig(config)) {
            let factory = this.container.get('security.firewall.provider.factory');
            let providers = this.container.get('config').get('security').providers;
            return new ChainProvider(config.map(id => factory.getProviderFromConfig(providers[id])));
        }

        if (isMemoryConfig(config)) {
            return new InMemoryProvider(this.container, config);
        }

        if (isBassConfig(config)) {
            return new BassProvider(this.container, config);
        }

        throw new InvalidArgumentError(
            'Unsupported configuration was used with conga-security:service/ProviderConfigService');
    }
}

module.exports = ProviderConfigService;