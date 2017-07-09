/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractProvider = require('./AbstractProvider');
const AbstractProviderConfig = require('./AbstractProviderConfig');
const InMemoryProvider = require('./InMemoryProvider');
const ChainProvider = require('./ChainProvider');
const ConfigurationError = require('./../../error/ConfigurationError');
const InvalidArgumentError = require('./../../error/InvalidArgumentError');

/**
 * Collection of registered provider configs
 * @type {Array<AbstractProviderConfig>}
 */
let providers = [];

/**
 * The provider factory is registered as a service, and is responsible for
 * instantiating providers attached to a firewall.
 */
class ProviderFactory {
    /**
     * @param {Object} container The service container
     */
    constructor(container) {
        this.container = container;
    }

    /**
     * Register a custom provider configuration
     * @param {AbstractProviderConfig} providerConfig The custom provider configuration to register
     * @returns {void}
     * @throws InvalidArgumentError for invalid providerConfig
     */
    registerProvider(providerConfig) {
        if (!(providerConfig instanceof AbstractProviderConfig)) {
            throw new InvalidArgumentError(
                'Your custom provider configuration must inherit from AbstractProviderConfig');
        }
        providers.push(providerConfig);
    }

    /**
     * Unregister a provider configuration by reference
     * @param {AbstractProviderConfig} providerConfig The custom provider configuration to unregister
     * @returns {void}
     */
    unregisterProvider(providerConfig) {
        const temp = [];

        for (let provider of providers) {
            if (provider !== providerConfig) {
                temp.push(provider);
            }
        }

        providers = temp;
    }

    /**
     * Get the provider for a firewall configuration
     * @param {Object} [firewall] The firewall configuration to use, if not provided, the current route is looked up
     * @returns {AbstractProvider|ChainProvider|InMemoryProvider|BassProvider|null}
     */
    getFirewallProvider(firewall = null) {
        if (!firewall) {
            firewall = this.container.get('security.firewall').getFirewallForRequest();
            if (!firewall) {
                return null;
            }
        }

        if (!firewall.provider) {
            return null;
        }

        const security = this.container.get('config').get('security');

        if (!security.providers || !(firewall.provider in security.providers)) {
            return null;
        }

        return this.getProviderFromConfig(security.providers[firewall.provider]);
    }

    /**
     * Get a Provider from a provider configuration value
     * @param {Object|Array|String} providerConfig The provider configuration
     * @returns {AbstractProvider|ChainProvider|InMemoryProvider|BassProvider|null}
     * @throws ConfigurationError for referencing a service id that is not registered
     * @throws ConfigurationError if the resolved provider does not inherit from AbstractProvider
     */
    getProviderFromConfig(providerConfig) {
        let provider = null;

        if (typeof providerConfig === 'string') {
            // service key was referenced from DI
            let serviceId = providerConfig.replace(/^@/, '');
            if (!this.container.has(serviceId)) {
                throw new ConfigurationError(
                    'Provider configuration contains an invalid service id reference, "' + providerConfig + '".');
            }
            provider = this.container.get(serviceId);
        } else if (providerConfig instanceof AbstractProvider) {
            // service instance was referenced in DI
            provider = providerConfig;
        } else if (providerConfig instanceof Object) {
            // a config object is specified, this means a custom built-in provider is being used
            // loop through the registered providers until we find one that supports this provider-config
            for (let customProvider of providers) {
                if (customProvider.supportsConfig(providerConfig)) {
                    provider = customProvider.useConfig(providerConfig);
                    if (provider) {
                        break;
                    }
                }
            }
        }

        // if we have a valid provider instance, return it
        if (provider instanceof AbstractProvider) {
            return provider;
        }

        // if we actually managed to match a provider to the config and it's not an instance of AbstractProvider
        // we throw a config error to let the developer know something went wrong
        if (provider && providerConfig) {
            throw new ConfigurationError(
                'Provider must be an instance of conga-security:security/provider/AbstractProvider');
        }

        return null;
    }
}

module.exports = ProviderFactory;