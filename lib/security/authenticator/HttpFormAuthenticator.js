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
const AbstractAuthenticator = require('./AbstractAuthenticator');
const AnonAuthToken = require('./../token/AnonAuthToken');
const PreAuthToken = require('./../token/PreAuthToken');
const AuthTokenCredentials = require('./../token/AuthTokenCredentials');

/**
 * The HTTP form authenticator is used to authenticate HTTP Post requests with form data
 */
class HttpFormAuthenticator extends AbstractAuthenticator {
    /**
     * {@inheritDoc}
     * @see AbstractAuthenticator.useConfig
     */
    useConfig(options = null) {
        if (!(options instanceof Object)) {
            return null;
        }
        if (!options.login_field ||
            !options.secret_field ||
            !options.action_route ||
            !options.view_route
        ) {
            return null;
        }
        return super.useConfig(options);
    }

    /**
     * {@inheritDoc}
     * @see AbstractAuthenticator.isAnonymousRoute
     */
    isAnonymousRoute(request) {
        return this.isRoute(request, this.options.view_route) ||
               this.isRoute(request, this.options.action_failed_route);
    }

    /**
     * {@inheritDoc}
     * @see AbstractAuthenticator.shouldRedirect
     */
    shouldRedirect(request, token) {
        if (!this.options.success_redirect_route) {
            return false;
        }

        if (this.isRoute(request, this.options.action_route)) {
            return this.options.success_redirect_route;
        }

        if (this.isRoute(request, this.options.view_route)) {
            return this.options.success_redirect_route;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     * @see AbstractAuthenticator.shouldRedirectError
     */
    shouldRedirectError(request, err, token = null) {
        // we redirect on errors for the action route, assuming the login attempt failed
        if (this.compare(request.method, 'POST') &&
            this.isRoute(request, this.options.action_route)
        ) {
            return this.options.action_failed_route || this.options.view_route;
        }
        return false;
    }

    /**
     * {@inheritDoc}
     * @see AbstractAuthenticator.createToken
     */
    createToken(request, realm = 'http-form') {
        const urlLen = request.originalUrl.length;
        const urlBuff = Buffer.from(request.originalUrl);

        // if it's the view-route, allow anonymous access
        if (this.options.view_route.length === urlLen &&
            crypto.timingSafeEqual(urlBuff, Buffer.from(this.options.view_route))
        ) {
            return Promise.resolve(new AnonAuthToken(realm));
        }

        // if it's not the view_route and it's not the action_route, fail
        if (!this.compare(request.method, 'POST') ||
            this.options.action_route.length !== urlLen ||
            !crypto.timingSafeEqual(urlBuff, Buffer.from(this.options.action_route))
        ) {
            return Promise.reject(this.getAccessDeniedError('Unauthorized', 401));
        }

        // if there are no authentication credentials on the request, respond in kind
        if (!(request.body instanceof Object) ||
            !(this.options.login_field in request.body) ||
            !(this.options.secret_field in request.body)
        ) {
            return Promise.reject(this.getAccessDeniedError('Unauthorized', 401));
        }

        const username = request.body[this.options.login_field];
        const password = request.body[this.options.secret_field];

        // resolve with the PreAuthToken
        return Promise.resolve(
            new PreAuthToken(new AuthTokenCredentials(username, password), realm)
        );
    }
}

module.exports = HttpFormAuthenticator;
