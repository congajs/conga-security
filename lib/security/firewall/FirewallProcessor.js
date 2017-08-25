/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// core libs
const crypto = require('crypto');

// local libs
const AnonAuthToken = require('./../token/AnonAuthToken');
const RedirectAuthToken = require('./../token/RedirectAuthToken');
const HttpError = require('./../../error/HttpError');
const AccessDeniedError = require('./../../error/AccessDeniedError');

/**
 * The FirewallProcessor processes a request through a firewall
 */
class FirewallProcessor {
    /**
     * Validate required roles
     * @param {String|Array} firewallRoles Role[s] assigned to the firewall
     * @param {String|Array} tokenRoles Role[s] assigned to the token
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

        if (!Array.isArray(firewallRoles)) {
            firewallRoles = [firewallRoles];
        }

        // if there are more firewall roles than token roles, validate fails
        if (firewallRoles.length > tokenRoles.length) {
            return false;
        }

        // if any of firewall roles are not specified in token roles, validation fails
        // NOTE: check all of the roles for safe timing
        let bool = true;
        for (let role of firewallRoles) {
            const len = role.length;
            const buf = Buffer.from(role);
            const filter = tokenRoles.filter(check => {
                return check.length === len &&
                       crypto.timingSafeEqual(Buffer.from(check), buf);
            });
            bool = bool && filter.length !== 0;
        }

        // validation succeeds
        return bool;
    }

    /**
     * Safely, see if two strings compare
     * @param {String} a
     * @param {String} b
     * @returns {boolean}
     */
    static compare(a, b) {
        return !!(a && b && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)));
    }

    /**
     *
     * @param {Object} [request] The express request object - if not provided, use current request
     * @param {Object} [firewall] The firewall configuration to use
     */
    constructor(request, firewall) {
        this.request = request;
        this.requestBuff = Buffer.from(request.originalUrl);
        this.requestLen = request.originalUrl.length;
        this.firewall = firewall;
        this.roles = firewall && firewall.roles || [];
        this.realm = firewall && firewall.__key;
        this.routes = firewall && firewall.routes || {};
        this.isStateful = firewall && firewall.stateless !== undefined && !firewall.stateless;
        this.isAnonymous = firewall && firewall.anonymous;
        this.isSimpleFirewall = true;
    }

    /**
     * Validate required roles
     * @param {String|Array} roles Role[s] assigned to the token
     * @returns {boolean}
     */
    validateRoles(roles) {
        return this.constructor.validateRoles(this.roles, roles);
    }

    /**
     * See if a route matches the request url
     * @param {String} route The route (url) to check for
     * @returns {boolean}
     */
    isRoute(route) {
        return !!(
            this.requestLen === route.length &&
            crypto.timingSafeEqual(this.requestBuff, Buffer.from(route))
        );
    }

    /**
     * See if the current request URL is the redirect route
     * @returns {boolean}
     */
    isRedirectRoute() {
        return this.firewall &&
               this.firewall.routes &&
               this.firewall.routes.redirect &&
               this.isRoute(this.firewall.routes.redirect);
    }

    /**
     * See if the current request URL is the logout route
     * @returns {boolean}
     */
    isLogoutRoute() {
        return this.firewall &&
               this.firewall.routes &&
               this.firewall.routes.logout &&
               this.firewall.routes.logout.path &&
               this.isRoute(this.firewall.routes.logout.path);
    }

    /**
     * Set the authenticator for this processor
     * @param {AbstractAuthenticator} authenticator
     * @returns {void}
     */
    setAuthenticator(authenticator) {
        this.authenticator = authenticator;
        this.isSimpleFirewall = !authenticator || !this.provider;
    }

    /**
     * Set the provider for this processor
     * @param {AbstractProvider} provider
     * @returns {void}
     */
    setProvider(provider) {
        this.provider = provider;
        this.isSimpleFirewall = !provider || !this.authenticator;
    }

    /**
     * Get an access denied error that supports the redirect route
     * @param {String} [msg] The error message
     * @param {Number} [status] The HTTP status to respond with
     * @returns {AccessDeniedError}
     */
    getAccessDeniedError(msg = 'Access Denied', status = 403) {
        const err = new AccessDeniedError(msg, status);
        if (this.firewall.routes && this.firewall.routes.redirect) {
            err.status = 302;
            err.addResponseHeader('Location', this.firewall.routes.redirect);
        }
        return err;
    }

    /**
     * Get a pre-auth token for this request
     * @returns {Promise.<AuthToken>}
     */
    getPreAuthToken() {
        if (!this.firewall ||
            this.isSimpleFirewall ||
            this.authenticator.isAnonymousRoute(this.request) ||
            this.isRedirectRoute()
        ) {
            return Promise.resolve(new AnonAuthToken(this.realm));
        }
        return this.authenticator.createToken(this.request, this.realm);
    }

    /**
     * Authenticate a token
     * @param {AuthToken} token The [pre]auth token to authenticate
     * @param {String} realm The security realm to authenticate against
     * @returns {Promise}
     */
    authenticateToken(token, realm) {
        // if we don't have a pre-auth token, access is denied unless the firewall is anonymous
        if (!token) {
            if (this.isAnonymous || this.isSimpleFirewall) {
                return Promise.resolve(new AnonAuthToken(realm));
            }
            return Promise.reject(this.getAccessDeniedError('Access Denied: Failed Pre-Auth'));
        }

        /* NOTE: "simple firewalls" will restrict roles but not provide an authenticator or
                 provider - they rely on sessions (or other listener) to provide previously
                 authenticated tokens */

        // if it's a simple firewall, return the token without authentication
        // with no authenticator / provider we can't authenticate
        if (this.isSimpleFirewall) {
            return Promise.resolve(token);
        }

        // if we got back a anon token as our pre-auth, send it through
        if (token instanceof AnonAuthToken) {
            return Promise.resolve(token);
        }

        // pre-auth-tokens are not pre-auth if already authenticated
        // do not authenticate twice
        if (token.authenticated) {
            return Promise.resolve(token);
        }

        // use the authenticator to authenticate the pre-auth-token
        return this.authenticator.authenticateToken(token, this.provider, realm);
    }

    /**
     * Validate a token
     * @param {AuthToken} token The auth token to validate
     * @returns {Promise}
     */
    validateToken(token) {

        // skip validation if we got back an anonymous token

        /* validation fails if:
              - we have no token
              - the token is not authenticated
              - the token roles do not validate */

        if (!(token instanceof AnonAuthToken) &&
            (!token || !token.authenticated || !this.validateRoles(token.roles))
        ) {
            if (this.isAnonymous || this.isSimpleFirewall) {
                // if the firewall is simple or anonymous, allow anonymous access
                return Promise.resolve(new AnonAuthToken(this.realm));
            }
            return Promise.reject(this.getAccessDeniedError());
        }

        /* NOTE: we use redirect-auth-tokens because we want to show that we succeeded.
                 the token will be saved in the session and the system will perform a
                 redirect - we don't want to use an error because technically nothing
                 went wrong */

        // redirect the request according to the authenticator
        if (this.authenticator) {
            const redirect = this.authenticator.shouldRedirect(this.request, token);
            if (redirect) {
                token = new RedirectAuthToken(token, redirect);
            }
        }

        // resolve with the authenticated token
        return Promise.resolve(token);
    }

    /**
     * Process the request through the firewall
     * @returns {Promise.<AuthToken>}
     */
    process() {
        // if this is the logout route, don't process anything
        if (this.isLogoutRoute()) {
            let err = new AccessDeniedError('Unauthorized', 401);
            const routes = this.routes;
            const redirect = routes.logout.target || routes.redirect;
            if (redirect) {
                const e = Object.create(err);
                e.previous = err;
                e.status = 302;
                e.addResponseHeader('Location', redirect);
                err = e;
            }
            return this.processCatcher(err);
        }
        // resolve a pre-auth token and then authenticate it
        return this.getPreAuthToken()
            .then(preAuthToken => this.authenticateToken(preAuthToken, this.realm))
            .then(token => this.validateToken(token))
            .catch(err => this.processCatcher(err));
    }

    /**
     * Catch error from processing a request (normal errors and 401, 403, 302, 500 http status codes)
     * @param {HttpError|Error} err
     * @returns {Promise}
     */
    processCatcher(err) {
        if (this.authenticator) {
            const redirect = this.authenticator.shouldRedirectError(this.request, err);
            if (redirect) {
                err = new HttpError(err.message, 302, err);
                err.addResponseHeader('Location', redirect);
            }
        }

        // if the error isn't already redirecting, use the redirect route on the firewall
        if (!err.headers || !('location' in err.headers)) {
            if (!this.isRedirectRoute() && this.routes.redirect) {
                err = new HttpError(err.message, 302, err);
                err.addResponseHeader('Location', this.routes.redirect);
            }
        }

        return Promise.reject(err);
    }
}

module.exports = FirewallProcessor;