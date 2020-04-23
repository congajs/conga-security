/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const FirewallProcessor = require('./FirewallProcessor');
const SessionFirewallProcessor = require('./SessionFirewallProcessor');

/**
 * The firewall factory is responsible for returning firewall objects.
 *   - resolve the firewall service
 *   - resolve firewall configuration based on different criteria
 *   - resolve a firewall request processor for a given request
 */
class FirewallFactory {
    /**
     *
     * @param {Container} container The service container
     */
    constructor(container) {
        this.container = container;
    }

    /**
     * Get the firewall service from the service container
     * @returns {Firewall}
     */
    getFirewallService() {
        return this.container.get('security.firewall');
    }

    /**
     * Get the firewall configuration object
     * @returns {Object|undefined}
     */
    getFirewallConfig() {
        if (!this._firewallConfig) {
            const security = this.container.get('config').get('security');
            if (security instanceof Object &&
                security.firewall instanceof Object
            ) {
                const keys = Object.keys(security.firewall);
                if (keys.length !== 0) {
                    this._firewallConfig = keys.reduce((obj, key) => {
                        // ... fixing the realms ...
                        const firewall = security.firewall[key];
                        if (!firewall.realm) {
                            firewall.realm = key;
                        }
                        obj[key] = firewall;
                        return obj;
                    }, {});
                }
            }
        }
        return this._firewallConfig;
    }

    /**
     * Get a firewall configuration object for a security realm
     * @param {String} realm The security realm to get a configuration for
     * @returns {Object|undefined}
     */
    getFirewallConfigForRealm(realm) {
        const firewall = this.getFirewallConfig() || {};
        return firewall[realm];
    }

    /**
     * Get a firewall configuration object for a given (or the current) request
     * @param {Object} request A conga express request object
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action that is handling the request
     * @returns {Object|null} The matching firewall configuration
     */
    getFirewallConfigForRequest(request, controller = null, action = null) {
        const firewall = this.getFirewallConfig();
        const security = this.container.get('config').get('security');
        let found = null;
        if (firewall) {
            // UNSURE: should we cache routes / controller+action to firewall config object?  performance?
            for (let key in firewall) {
                // if the firewall is attached to the controller, use that first
                let config = security.firewall[key];
                if (controller && config.controller === controller &&
                    (!action || config.action === undefined || config.action === action)
                ) {
                    config.__key = key;
                    found = config;
                    this.container.get('logger')
                        .debug('[conga-security] - firewall ' + key + ' ' + found.route);
                    break;
                } else if (!found) {
                    let regexp = new RegExp(config.route);
                    if (regexp.test(request.originalUrl)) {
                        config.__key = key;
                        found = config;
                        // continue, as we may find a matching controller + action
                    }
                }
            }
        }
        return found;
    }

    /**
     * Get a firewall processor for a request
     * @param {Object} [request] An express request object, or undefined / null - if not provided, use current request
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action that is handling the request* @param action
     * @returns {FirewallProcessor}
     */
    getProcessorForRequest(request, controller = null, action = null) {
        const firewall = this.getFirewallConfigForRequest(request, controller, action);

        const isStateful = firewall && firewall.stateless !== undefined && !firewall.stateless;
        const hasSessionMixin = request.session && request.session.getSecurityContext;

        let processor;

        if (isStateful && hasSessionMixin) {
            processor = new SessionFirewallProcessor(request, firewall);
            processor.setFirewallFactory(this);
            processor.setProviderFactory(this.container.get('security.firewall.provider.factory'));
        } else {
            processor = new FirewallProcessor(request, firewall);
        }

        if (firewall) {
            processor.setAuthenticator(
                this.container.get('security.firewall.authenticator.factory')
                    .getFirewallAuthenticator(firewall)
            );
            processor.setProvider(
                this.container.get('security.firewall.provider.factory')
                    .getFirewallProvider(firewall)
            );
            /*if (this.container.has('profiler.stopwatch')) {
                processor.setStopwatch(this.container.get('profiler.stopwatch'));
            }*/
        } else {
            this.container.get('logger').debug('[conga-security] - no firewall found for request');
        }

        return processor;
    }
}

module.exports = FirewallFactory;