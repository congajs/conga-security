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
const ConfigurationError = require('./../../error/ConfigurationError');
const InvalidArgumentError = require('./../../error/InvalidArgumentError');

/**
 * Collection of registered provider config service-ids
 * @type {Array<String>}
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
     * @param {String} sid The custom provider configuration service id to register
     * @returns {void}
     * @throws InvalidArgumentError for invalid providerConfig
     */
    registerProvider(sid) {
        const providerConfig = this.container.has(sid) && this.container.get(sid);
        if (!(providerConfig instanceof AbstractProviderConfig)) {
            throw new InvalidArgumentError(
                'Your custom provider configuration must inherit from AbstractProviderConfig');
        }
        providers.push(sid);
    }

    /**
     * Unregister a provider configuration by reference
     * @param {String} sid The custom provider configuration service id to unregister
     * @returns {void}
     */
    unregisterProvider(sid) {
        const temp = [];

        for (let provider of providers) {
            if (provider !== sid) {
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
        // make sure we have a firewall
        if (!firewall) {
            firewall = this.container.get('security.firewall').getFirewallForRequest();
            if (!firewall) {
                return null;
            }
        }

        // make sure we have a provider
        if (!firewall.provider) {
            return null;
        }

        // support for service-id provider values and object references
        if (firewall.provider instanceof Object || firewall.provider[0] === '@') {
            return this.getProviderFromConfig(firewall.provider);
        }

        // check for the mapped provider in the sercurity.providers config
        const security = this.container.get('config').get('security');
        if (!security.providers || !(firewall.provider in security.providers)) {
            return null;
        }

        // found a valid config, return its provider
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

        if (typeof providerConfig === 'string' && providerConfig[0] === '@') {
            // service key was referenced from DI
            let serviceId = providerConfig.substr(1);
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
            for (let customProviderSid of providers) {
                const customProvider = this.container.get(customProviderSid);
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
                'Provider must be an instance of @conga/framework-security/lib/security/provider/AbstractProvider.');
        }

        return null;
    }
}

module.exports = ProviderFactory;