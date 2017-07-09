/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const HttpError = require('./../error/HttpError');
const AccessDeniedError = require('./../error/AccessDeniedError');
const ConfigurationError = require('./../error/ConfigurationError');
const InvalidArgumentError  = require('./../error/InvalidArgumentError');
const AbstractAuthenticator = require('./authenticator/AbstractAuthenticator');
const AuthToken = require('./token/AuthToken');
const PreAuthToken = require('./token/PreAuthToken');

/**
 * Validate required roles
 * @param {String|Array} firewallRoles Array of roles required by the firewall
 * @param {String|Array} tokenRoles Array of roles assigned to the token
 * @returns {boolean}
 */
const validateRoles = (firewallRoles, tokenRoles) => {
    // if we have no firewall roles, validation always succeeds
    if (!firewallRoles || firewallRoles.length === 0) {
        return true;
    }

    // no token roles is only allowed when firewall roles are empty
    if (!tokenRoles || tokenRoles.length === 0) {
        return false;
    }

    if (!Array.isArray(tokenRoles)) {
        tokenRoles = [tokenRoles];
    }

    // if firewall roles is scalar, validate it directly
    if (!Array.isArray(firewallRoles)) {
        return tokenRoles.indexOf(firewallRoles) !== -1;
    }

    // if any of firewall roles are not specified in token roles, validation fails
    for (let role of firewallRoles) {
        if (tokenRoles.indexOf(role) === -1) {
            return false;
        }
    }

    // validation succeeds
    return true;
};

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
     * Get the firewall configuration object
     * @returns {Object|undefined}
     */
    getFirewallConfig() {
        if (!this._firewallConfig) {
            const security = this.container.get('config').get('security');
            if (security instanceof Object &&
                security.firewall instanceof Object &&
                Object.keys(security.firewall).length !== 0
            ) {
                this._firewallConfig = security.firewall;
            }
        }
        return this._firewallConfig;
    }

    /**
     * Get a firewall configuration object for a given (or the current) request
     * @param {Object} [request] An express request object, or undefined / null - if not provided, use current request
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action that is handling the request
     * @returns {Object|null} The matching firewall configuration
     */
    getFirewallForRequest(request = null, controller = null, action = null) {
        const firewall = this.getFirewallConfig();
        const security = this.container.get('config').get('security');
        let found = null;
        if (firewall) {
            if (!request) {
                request = this.container.get('request') || {};
            }
            // UNSURE: should we cache routes / controller+action to firewall config object?  performance?
            for (let key in firewall) {
                // if the firewall is attached to the controller, use that first
                let config = security.firewall[key];
                if (controller && config.controller && config.controller === controller &&
                    (!action || config.action === undefined || config.action === action)
                ) {
                    config.__key = key;
                    found = config;
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
     * Process a request with a specific firewall setting
     * @param {Object} [request] The express request object - if not provided, use current request
     * @param {String} [controller] The controller (service id) that is responding to this request
     * @param {String} [action] The controller action (method name) that is handling the request
     * @returns {Promise}
     * @throws InvalidArgumentError for an invalid request object
     * @throws ConfigurationError when an authenticator is not found
     * @throws ConfigurationError when a provider is not found
     */
    processRequest(request = null, controller = null, action = null) {
        return new Promise((resolve, reject) => {

            let stopwatch = this.container.has('profiler.stopwatch') && this.container.get('profiler.stopwatch');
            let fail = reject;
            if (stopwatch) {
                stopwatch = stopwatch.request(request);
                stopwatch.start('security.firewall', 'security');
                fail = err => {
                    stopwatch.ensureStopped();
                    reject(err);
                };
            }

            if (!request) {
                request = this.container.get('request');
                if (!request) {
                    throw new InvalidArgumentError('Could not find the request object.');
                }
            }

            const firewall = this.getFirewallForRequest(request, controller, action);
            const realm = firewall && firewall.__key;
            const security = this.container.get('config').get('security');

            // initialize with no token
            let token = null;

            // if sessions are supported for this realm, see if the auth token exists there
            // if (!token && firewall.stateless !== undefined && !firewall.stateless) {
            //     // TODO: get the current authentication token (from existing session, if any)
            // }

            // if we have no firewall, assume access is granted
            if (!firewall) {
                stopwatch && stopwatch.ensureStopped();
                resolve(token || new PreAuthToken());
                return;
            }

            this.container.get('logger').debug(
                '[conga-security] - firewall - ' + firewall.__key + ' ' + firewall.route);

            // if there's no authenticator or provider, just validate the roles
            if (firewall.anonymous || !firewall.authenticator || !firewall.provider) {
                // check the roles on the token against the firewall roles to validate auth
                if (firewall.anonymous || validateRoles(firewall.roles || [], (token && token.roles) || [])) {
                    stopwatch && stopwatch.ensureStopped();
                    resolve(token || new PreAuthToken());
                } else {
                    fail(new AccessDeniedError());
                }
                return;
            }

            // get and validate authenticator
            const authenticator = security.authenticators &&
                this.container.get(security.authenticators[firewall.authenticator].replace(/^@/, ''));

            if (!(authenticator instanceof AbstractAuthenticator)) {
                throw new ConfigurationError('Security firewall authenticator not found or is invalid.');
            }

            // get and validate the provider
            const provider = this.container.get('security.firewall.provider.factory').getFirewallProvider(firewall);
            if (!provider) {
                throw new ConfigurationError('Security firewall provider not found.');
            }

            // finish callback
            const finish = (token) => {
                // check the roles on the token against the firewall roles to validate auth
                if (!token || !token.authenticated || !validateRoles(firewall.roles, token.roles)) {
                    fail(new AccessDeniedError());
                    return;
                }

                // resolve with the token, we are done
                stopwatch && stopwatch.ensureStopped();
                resolve(token);
            };

            // if we have an existing supported token, use it
            if (token && authenticator.supportsToken(token, realm)) {

                authenticator.refreshToken(token, provider, realm)
                    .then(finish)
                    .catch(fail);

                return;

            }

            // use authenticator to get an authentication token
            authenticator.createToken(request, realm).then(preAuthToken => {

                if (!preAuthToken) {
                    fail(new AccessDeniedError('Access Denied: Failed Pre-Auth'));
                    return;
                }

                authenticator.authenticateToken(preAuthToken, provider, realm)
                    .then(authToken => finish(authToken || preAuthToken))
                    .catch(fail);

            }).catch(fail);

        });
    }
}

module.exports = Firewall;
