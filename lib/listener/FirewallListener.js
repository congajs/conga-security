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
const HttpError = require('./../error/HttpError');
const AccessDeniedError = require('./../error/AccessDeniedError');

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
            providerFactory.registerProvider(container.get(provider.getServiceId()));
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

        // if processRequest successfully retrieves an authentication token, it will resolve the promise with the token

        // if processRequest does not retrieve an authentication token, it will pass an Error object to reject
        // we need to use this error object to return an appropriate response

        const { request, response, container, action } = event;

        container.get('security.firewall').processRequest(request, request.conga.route.controller, action).then(token => {

            if (!token) {
                let err = new AccessDeniedError();
                response.return(err, err.status);
                return;
            }

            // TODO: add the token to the session realm

            container.get('security.context').setAuthToken(token);
            next();

        }).catch(err => {

            if (!(err instanceof SecurityError)) {
                err = new SecurityError(err.message, err);
            }

            // TODO: remove this check after 2.0 is released, response.error will be the correct way to handle
            if (typeof response.error === 'function') {
                response.error(err, err.status || 500);
                return;
            }

            // backwards compatibility (TODO: remove me after 2.0 is released)
            if (err instanceof HttpError) {
                if (err.hasResponseHeaders()) {
                    response.set(err.getResponseHeaders());
                }
            } else {
                console.error(err.stack || err);
            }

            let body = err;
            if (!request.isJson()) {
                body = err.message;
            }

            response.send(err.status || 500, body);

        });
    }
}

module.exports = FirewallListener;