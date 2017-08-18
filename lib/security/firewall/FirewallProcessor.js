/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AnonAuthToken = require('./../token/AnonAuthToken');
const RedirectAuthToken = require('./../token/RedirectAuthToken');

/**
 * The FirewallProcessor processes a request through a firewall
 */
class FirewallProcessor {
    /**
     * Validate required roles
     * @param {String|Array} firewallRoles Array of roles required by the firewall
     * @param {String|Array} tokenRoles Array of roles assigned to the token
     * @returns {boolean}
     */
    static validateRoles(firewallRoles, tokenRoles) {
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
    }

    /**
     *
     * @param {Object} [request] The express request object - if not provided, use current request
     * @param {Object} [firewall] The firewall configuration to use
     */
    constructor(request, firewall) {
        this.request = request;
        this.firewall = firewall;
        this.roles = firewall && firewall.roles || [];
        this.realm = firewall && firewall.__key;
        this.isStateful = firewall && firewall.stateless !== undefined && !firewall.stateless;
        this.isAnonymous = firewall && firewall.anonymous;
    }

    /**
     * Set the authenticator for this processor
     * @param {AbstractAuthenticator} authenticator
     * @returns {void}
     */
    setAuthenticator(authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Set the provider for this processor
     * @param {AbstractProvider} provider
     * @returns {void}
     */
    setProvider(provider) {
        this.provider = provider;
    }

    /**
     * Get a pre-auth token for this request
     * @returns {Promise.<AuthToken>}
     */
    getPreAuthToken() {
        if (!this.authenticator || !this.provider) {
            return Promise.resolve(new AnonAuthToken(this.realm));
        }
        return this.authenticator.createToken(this.request, this.realm);
    }

    /**
     * Process the request through the firewall
     * @returns {Promise.<AuthToken>}
     */
    process() {
        // pull out some members from our instance, for the closures
        const { firewall, authenticator, provider, realm, roles, request, isAnonymous } = this;

        if (!firewall) {
            // if we have no firewall, assume access is granted
            return Promise.resolve(new AnonAuthToken(realm));
        }

        // if it's the redirect route, allow anonymous access
        if (authenticator && authenticator.isAnonymousRoute(request)) {
            return Promise.resolve(new AnonAuthToken(realm));
        }

        /* NOTE: "simple firewalls" will restrict roles but not provide an authenticator or
                 provider - they rely on sessions (or other listener) to provide previously
                 authenticated tokens */

        // see if this is a simple firewall
        const isSimpleFirewall = !authenticator || !provider;

        // resolve a pre-auth token and then authenticate it
        return this.getPreAuthToken().then(preAuthToken => {

            // if we don't have a pre-auth token, access is denied unless the firewall is anonymous
            if (!preAuthToken) {
                if (isAnonymous) {
                    return new AnonAuthToken(realm);
                }
                return Promise.reject(authenticator.getAccessDeniedError(
                    'Access Denied: Failed Pre-Auth'));
            }

            // if it's a simple firewall, return the token without authentication
            // with no authenticator / provider we can't authenticate
            if (isSimpleFirewall) {
                return preAuthToken;
            }

            // if we got back a anon token as our pre-auth, send it through
            if (preAuthToken instanceof AnonAuthToken) {
                return preAuthToken;
            }

            // pre-auth-tokens are not pre-auth if already authenticated
            // do not authenticate twice
            if (preAuthToken.authenticated) {
                return preAuthToken;
            }

            // use the authenticator to authenticate the pre-auth-token
            return authenticator.authenticateToken(preAuthToken, provider, realm);

            // the promise chain is split up here because we want to allow tokens that have
            // already been authenticated to pass without authenticating twice

        }).then(token => {

            // skip validation if we got back an anonymous token

            /* validation fails if:
                  - we have no token
                  - the token is not authenticated
                  - the token roles do not validate */

            if (!(token instanceof AnonAuthToken) &&
                !token ||
                !token.authenticated ||
                !this.constructor.validateRoles(roles, token.roles || [])
            ) {
                if (isAnonymous || isSimpleFirewall) {
                    // if the firewall is simple or anonymous, allow anonymous access
                    return new AnonAuthToken(realm);
                }
                return Promise.reject(authenticator.getAccessDeniedError());
            }

            // redirect the request according to the authenticator
            const redirect = authenticator && authenticator.shouldRedirect(request, token);
            if (redirect) {
                return new RedirectAuthToken(token, redirect);
            }

            // resolve with the authenticated token
            return token;

        });

    }

}

module.exports = FirewallProcessor;