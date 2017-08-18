/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// core libs
const path = require('path');

// local libs
const FirewallAnnotation = require('./../FirewallAnnotation');
const ConfigurationError = require('./../../error/ConfigurationError');

/**
 * The paths to all the annotations we support
 * @type {Array<String>}
 */
const paths = [
    path.join(__dirname, '..', 'FirewallAnnotation')
];

/**
 * The ControllerAnnotationHandler registers and processes custom controller annotations for the conga-security bundle
 */
class ControllerAnnotationHandler {
    /**
     * Get all annotation paths
     * @returns {Array<String>}
     */
    getAnnotationPaths() {
        return paths;
    }

    /**
     * Process all the annotations through the reader
     * @param {Object} container The service container
     * @param {Object} reader The annotation reader
     * @param {{filePath:String}} controller The controller config object
     */
    handleAnnotations(container, reader, controller) {
        // parse the annotations
        reader.parse(controller.filePath);

        // handle the @Firewall annotations
        this.handleFirewallAnnotations(container, reader, controller);
    }

    /**
     * Process all the @Firewall annotations through the reader
     * @param {Object} container The service container
     * @param {Object} reader The annotation reader
     * @param {{filePath:String}} controller The controller config object
     */
    handleFirewallAnnotations(container, reader, controller) {
        const { routes } = container.get('conga.controller.routing.annotations.handler')
                                    .parseRoutesFromFile(container, reader, controller);

        const security = container.get('config').get('security');

        if (!security.firewall) {
            security.firewall = {};
        }

        // annotation firewalls get prepended
        const firewall = {};

        // keep track of methods we register a firewall for
        const methodRoutes = {};

        // register firewalls for all annotated methods
        for (let annotation of reader.methodAnnotations) {
            if (annotation instanceof FirewallAnnotation) {
                if (!annotation.anonymous && !annotation.roles &&
                        (!annotation.provider || !annotation.authenticator)
                ) {
                    throw new ConfigurationError(
                        'Your @Firewall annotation must either be anonymous, contain access roles, or have an authenticator and a provider.');
                }
                // find the route that is attached to this method (if any)
                for (let i in routes) {
                    if (routes[i].action === annotation.target) {
                        // register the method annotation as the firewall, using the attached route we found
                        // do not overwrite existing firewall realms
                        let realm = annotation.realm || routes[i].name || annotation.target;
                        if (!(realm in firewall)) {
                            if (annotation.authenticator &&
                                !security.authenticators[annotation.authenticator]
                            ) {
                                if (annotation.authenticator[0] !== '@') {
                                    throw new ConfigurationError(
                                        'Your @Firewall annotation has an invalid authenticator.');
                                }
                                security.authenticators[annotation.authenticator] = annotation.authenticator;
                            }
                            if (annotation.provider && !security.providers[annotation.provider]) {
                                if (annotation.provider[0] !== '@') {
                                    throw new ConfigurationError(
                                        'Your @Firewall annotation has an invalid provider.');
                                }
                                security.providers[annotation.provider] = annotation.provider;
                            }
                            firewall[realm] = Object.assign({}, annotation, {
                                realm,
                                route: annotation.route || routes[i].path.replace(/:[^\/]+/g, '[^/]+'),
                                controller: routes[i].controller,
                                action: routes[i].action
                            });
                            methodRoutes[i] = firewall[realm];
                        }
                        break;
                    }
                }
            }
        }

        // handle the definition, only one is allowed
        for (let annotation of reader.definitionAnnotations) {
            if (annotation instanceof FirewallAnnotation) {

                if (!annotation.provider || !annotation.authenticator) {
                    throw new ConfigurationError(
                        'Your @Firewall annotation is not configured correctly.');
                }

                let realm = annotation.realm || annotation.target;

                if (annotation.route) {
                    // register the definition as the firewall
                    // we assume that all methods which are not annotated fall under this realm via route regexp
                    // do not overwrite existing firewall realms
                    if (!(realm in firewall)) {
                        if (!security.authenticators[annotation.authenticator]) {
                            if (annotation.authenticator[0] !== '@') {
                                throw new ConfigurationError(
                                    'Your @Firewall annotation has an invalid authenticator.');
                            }
                            security.authenticators[annotation.authenticator] = annotation.authenticator;
                        }
                        if (!security.providers[annotation.provider]) {
                            if (annotation.provider[0] !== '@') {
                                throw new ConfigurationError(
                                    'Your @Firewall annotation has an invalid provider.');
                            }
                            security.providers[annotation.provider] = annotation.provider;
                        }
                        firewall[ realm ] = Object.assign({}, annotation, { realm });
                    }
                }

                // register each method that's not already registered, if the definition doesn't have a prefix or route
                for (let i in routes) {
                    // methodRoutes let us know if there is an annotated Firewall for the route at the same index
                    // if there is not one already defined, we need to create one for this method's route
                    // do not overwrite existing firewall realms
                    if (!(i in methodRoutes)) {
                        let useRealm = realm + '_' + (routes[i].name || routes[i].action);
                        if (!(useRealm in firewall)) {
                            if (!security.authenticators[annotation.authenticator]) {
                                if (annotation.authenticator[0] !== '@') {
                                    throw new ConfigurationError(
                                        'Your @Firewall annotation has an invalid authenticator.');
                                }
                                security.authenticators[annotation.authenticator] = annotation.authenticator;
                            }
                            if (!security.providers[annotation.provider]) {
                                if (annotation.provider[0] !== '@') {
                                    throw new ConfigurationError(
                                        'Your @Firewall annotation has an invalid provider.');
                                }
                                security.providers[annotation.provider] = annotation.provider;
                            }
                            firewall[useRealm] = Object.assign({}, annotation, {
                                realm: useRealm,
                                route: annotation.route || routes[i].path.replace(/:[^\/]+/g, '[^/]+'),
                                controller: routes[i].controller,
                                action: routes[i].action
                            });
                        }
                    }
                }

                break;
            }
        }

        security.firewall = Object.assign({}, firewall, security.firewall);
    }
}

module.exports = ControllerAnnotationHandler;