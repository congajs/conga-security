/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const SecurityError = require('./../error/SecurityError');
const AccessDeniedError = require('./../error/AccessDeniedError');
const AuthToken = require('./../security/token/AuthToken');
const RedirectAuthToken = require('./../security/token/RedirectAuthToken');

/**
 * The firewall listener is used to authenticate or block access to routes / controllers
 */
class FirewallListener {
    /**
     * Process firewall config on kernel compile
     * @param {Object} event The event object
     * @param {Function} next The function to invoke the next event listener in the series
     * @returns {void}
     */
    onKernelCompile(event, next) {

        // find all the tagged firewall providers
        const { container } = event;
        const providers = container.getTagsByName('security.firewall.provider');

        // if we have no tagged providers, move on
        if (!providers || providers.length === 0) {
            next();
            return;
        }

        // sort the tags by priority
        container.get('conga.ioc.tag.sorter').sortByPriority(providers);

        // add each tagged provider to the provider factory
        const providerFactory = container.get('security.firewall.provider.factory');

        for (let provider of providers) {
            providerFactory.registerProvider(provider.getServiceId());
        }

        // we are done
        next();
    }

    /**
     * Check the firewall settings for the current route, before the controller is executed
     * @param {Object} event The event object
     * @param {Function} next The function to invoke the next event listener in the series
     * @returns {void}
     */
    onPreController(event, next) {

        const { request, response, container, action } = event;
        const sid = request.conga.route.controller;

        const stopwatch = container.has('profiler.stopwatch') &&
            container.get('profiler.stopwatch').request(request, 'security.firewall');

        let stopwatchEvent = stopwatch && stopwatch.start();

        container.get('security.firewall').processRequest(request, sid, action).then(token => {

            // if we didn't get a token back, access denied
            if (!(token instanceof AuthToken)) {
                let err = new AccessDeniedError();
                response.error(err, err.status);
                stopwatchEvent && stopwatchEvent.stop();
                return;
            }

            // set the token in the security.context
            container.get('security.context').setAuthToken(token);

            // if the token is packaged in a RedirectAuthToken, perform the redirect
            if (token instanceof RedirectAuthToken && token.location) {
                stopwatchEvent && stopwatchEvent.stop();
                response.redirect(302, token.location);
                return;
            }

            stopwatchEvent && stopwatchEvent.stop();

            // continue on to the next pre-controller listener
            next();

        }).catch(err => {

            if (!(err instanceof SecurityError)) {
                err = new SecurityError(err.message, err);
            }

            stopwatchEvent && stopwatchEvent.stop();

            response.error(err, err.status || 500);

        });
    }
}

module.exports = FirewallListener;