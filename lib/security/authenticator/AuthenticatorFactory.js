/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractAuthenticator = require('./AbstractAuthenticator');
const ConfigurationError = require('./../../error/ConfigurationError');

/**
 * The AuthenticatorFactory is responsible for returning authenticators
 * from configuration directives
 */
class AuthenticatorFactory {

    /**
     *
     * @param {Container} container The service container
     */
    constructor(container) {
        this.container = container;
    }

    /**
     * Get an authenticator service from its service id
     * @param {String} sid The service id
     * @return {null|AbstractAuthenticator|*}
     */
    getAuthenticatorFromServiceId(sid) {
        let serviceId = sid.replace(/^@/, '');
        if (!this.container.has(serviceId)) {
            return null;
        }
        return this.container.get(serviceId);
    }

    /**
     * Get the authenticator for a firewall configuration
     * @param {Object} [firewall] The firewall configuration to use, if not provided, the current route is looked up
     * @returns {AbstractAuthenticator|null}
     */
    getFirewallAuthenticator(firewall = null) {
        if (!firewall) {
            firewall = this.container.get('security.firewall').getFirewallForRequest();
            if (!firewall) {
                return null;
            }
        }

        if (!firewall.authenticator) {
            return null;
        }

        if (typeof firewall.authenticator === 'string' && firewall.authenticator[0] !== '@') {

            // if it's a string without @, assume at this points it's a reference to key in the
            // security.authenticators configuration section
            const security = this.container.get('config').get('security');
            if (security.authenticators && firewall.authenticator in security.authenticators) {
                return this.getAuthenticatorFromConfig(
                    security.authenticators[firewall.authenticator]);
            }

            // if the key doesn't exist fail
            return null;
        }

        // try to resolve the authenticator from the config
        return this.getAuthenticatorFromConfig(firewall.authenticator);
    }

    /**
     * Get an authenticator from configuration
     * @param {String|Function|Object} config The authenticator configuration (security.authenticators.my_authenticator)
     * @throws ConfigurationError
     */
    getAuthenticatorFromConfig(config) {
        let authenticator = null;
        let options = null;

        const security = this.container.get('config').get('security');

        // get the authenticator from the config argument
        // it can be a string or an object of different types

        if (typeof config === 'string') {

            // service id was referenced
            authenticator = this.getAuthenticatorFromServiceId(config);
            if (!authenticator) {
                throw new ConfigurationError(
                    'Authenticator configuration contains an invalid service id reference, "' +
                    config + '"');
            }

        } else if (config instanceof Function) {

            // the configuration is a function that returns the authenticator
            authenticator = config();

        } else if (config instanceof AbstractAuthenticator) {

            // service instance was referenced
            authenticator = config;

        } else if (config instanceof Object) {

            // custom authenticator configuration object
            options = Object.create(config.options || {});

            // if the security.authenticator id is referenced, use that
            if (config.id !== undefined) {
                // an authenticator key id is being referenced, defined in security.authenticators
                if (security.authenticators && config.id in security.authenticators) {
                    return this.getAuthenticatorFromConfig(
                        Object.assign({}, security.authenticators[config.id], options));
                }
            }

            // if a service id was referenced, use that
            let customAuthenticator;
            if (config.service !== undefined) {
                // a service id is being referenced
                customAuthenticator = this.getAuthenticatorFromServiceId(config.service);
            }

            // make sure we found a valid authenticator
            if (!(customAuthenticator instanceof Object)) {
                throw new ConfigurationError(
                    'Authenticator configuration contains an invalid reference, "' +
                        config.service + '"');
            }

            if (customAuthenticator instanceof Function) {
                // get the authenticator from the function
                authenticator = customAuthenticator(options);
            } else {
                // a service id was specified, but no other options
                authenticator = customAuthenticator;
            }
        }

        // if the authenticator has a factory method, call it to get the authenticator instance
        if (authenticator && options) {
            if (authenticator.useConfig instanceof Function) {
                // get the authenticator from the useConfig factory method
                authenticator = authenticator.useConfig(options);
            } else if (authenticator instanceof Function) {
                // a factory function was mapped, get the authenticator from it
                authenticator = authenticator(options);
            }
        }

        // if we have a valid authenticator instance, return it
        if (authenticator instanceof AbstractAuthenticator) {
            return authenticator;
        }

        // if we actually managed to match an authenticator to the config and it's not an instance
        // of AbstractAuthenticator we throw a config error to let the developer know that
        // something went wrong
        if (authenticator && config) {
            throw new ConfigurationError(
                'Authenticator must be an instance of @conga/framework-security/lib/security/authenticator/AbstractAuthenticator');
        }

    }

}

module.exports = AuthenticatorFactory;