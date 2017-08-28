/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const InvalidArgumentError  = require('./../../error/InvalidArgumentError');

/**
 * The Firewall class handles requests through configured firewall settings
 */
class Firewall {
    /**
     * @param {Object} container The service container
     */
    constructor(container) {
        this.container = container;
    }

    /**
     * Get the firewall factory
     * @returns {FirewallFactory}
     */
    factory() {
        return this.container.get('security.firewall.factory');
    }

    /**
     * @see FirewallFactory.getFirewallConfig
     */
    getFirewallConfig() {
        return this.factory().getFirewallConfig();
    }

    /**
     * @see FirewallFactory.getFirewallConfigForRealm
     */
    getFirewallForRealm(realm) {
        return this.factory().getFirewallConfigForRealm(...arguments);
    }

    /**
     * @see FirewallFactory.getFirewallConfigForRequest
     */
    getFirewallForRequest(request, controller = null, action = null) {
        return this.factory().getFirewallConfigForRequest(...arguments);
    }

    /**
     * Get the security / firewall realm for a given (or the current) request
     * @param {Object} request A conga express request object
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action that is handling the request
     * @returns {String|null}
     */
    getRealmForRequest(request, controller = null, action = null) {
        const firewall = this.getFirewallForRequest(request, controller, action);
        return (firewall && firewall.__key) || null;
    }

    /**
     * Process a request with a specific firewall setting
     * @param {Object} [request] The conga express request object - if not provided, use current request
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action (method name) that is handling the request
     * @returns {Promise}
     * @throws InvalidArgumentError for an invalid request object
     * @throws ConfigurationError when an authenticator is not found
     * @throws ConfigurationError when a provider is not found
     */
    processRequest(request = null, controller = null, action = null) {
        if (!request) {
            request = this.container.get('request');
            if (!request) {
                throw new InvalidArgumentError('Could not find a request object.');
            }
        }
        return this.factory()
            .getProcessorForRequest(request, controller, action)
            .process();
    }
}

module.exports = Firewall;
