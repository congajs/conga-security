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
const ConfigurationError = require('./../../error/ConfigurationError');

/**
 * Execute a method on every provider in the chain, in series, until one of them returns a valid response
 * @param {Array<AbstractProvider>} chain The provider chain
 * @param {String} providerFn The function on the provider to execute ('getResource', 'refreshResource')
 * @param {Function} fn The function to recurse (the function that initiated this request)
 * @param {Array} fnArgs Arguments that will be passed to both the providerFn and fn
 * @returns {Promise}
 * @throws ConfigurationError on invalid provider
 */
const chainResourceFn = (chain, providerFn, fn, fnArgs) => {
    const provider = chain.shift();
    if (!provider) {
        return Promise.resolve(null);
    }
    if (!(provider instanceof AbstractProvider)) {
        throw new ConfigurationError(
            'Invalid chain provider; one or more providers do not inherit from AbstractProvider.');
    }
    return provider[providerFn](...fnArgs).then(resource => {
        if (!resource) {
            // NOTE: chain is always passed to the fn for recursion, as the last argument
            return fn(...fnArgs, chain);
        }
        return Promise.resolve(resource);
    });
};

/**
 * Get the first resource from a chain of providers
 * @param {AuthTokenCredentials|*} credentials The secret password / api key, etc.
 * @param {Array<AbstractProvider>} chain The provider chain
 * @returns {Promise}
 * @throws ConfigurationError on invalid provider
 */
const getResourceFromChain = (credentials, chain) => {
    return chainResourceFn(chain, 'getResource', getResourceFromChain, [credentials]);
};

/**
 * Get the first resource from a chain of providers, by calling refreshResource
 * @param {AuthResource|*} resource The authenticated resource being refreshed
 * @param {Array<AbstractProvider>} chain The provider chain
 * @returns {Promise}
 * @throws ConfigurationError on invalid provider
 */
const refreshResourceFromChain = (resource, chain) => {
    return chainResourceFn(chain, 'refreshResource', refreshResourceFromChain, [resource]);
};

/**
 * The chain provider allows you to group multiple providers together, so authentication
 * can be granted from any one of them
 */
class ChainProvider extends AbstractProvider {
    /**
     * Construct the chain-provider with a chain of AbstractProvider instances
     * @param {Array<AbstractProvider>} chain
     */
    constructor(chain = []) {
        super(chain);

        // the chain is the config
        this.chain = this.config;
    }

    /**
     * {@inheritDoc}
     */
    supportsResource(resource) {
        for (let provider of this.chain) {
            if (provider.supportsResource(resource)) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@inheritDoc}
     * @throws ConfigurationError on invalid provider
     */
    getResource(credentials) {
        return getResourceFromChain(credentials, this.chain.slice());
    }

    /**
     * {@inheritDoc}
     * @throws ConfigurationError on invalid provider
     */
    refreshResource(resource) {
        return refreshResourceFromChain(resource, this.chain.slice());
    }
}

module.exports = ChainProvider;