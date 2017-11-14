// framework libs
const { Controller } = require('@conga/framework');

/**
 * @Route("/_conga/api/security")
 */
class SecurityController extends Controller {
    /**
     * Get the security configuration
     * @returns {SecurityController.encryption|*}
     */
    getSecurityConfig() {
        return this.container.get('config').get('security');
    }

    /**
     * @Route("/", methods=['GET'])
     */
    main(req, res) {
        return Promise.resolve({

        });
    }

    /**
     * @Route("/encryption", methods=['GET'])
     */
    encryption(req, res) {
        const config = this.getSecurityConfig();
        const keys = Object.keys(config.encryption);
        return Promise.resolve({
            total: keys.length,
            strategies: keys.reduce((arr, key) => {
                const node = config.encryption[key];

                const opts = Object.assign({}, node);
                'algorithm' in opts && delete opts.algorithm;
                'path' in opts && delete opts.path;
                'encode_as_base64' in opts && delete opts.encode_as_base64;

                arr.push({
                    id: key,
                    algo: node.algorithm,
                    path: node.path,
                    encoding: node.encode_as_base64 === true ? 'Base64' : 'No',
                    options: Object.keys(opts).reduce((val, key) => {
                        val.push({
                            key: key,
                            value: opts[key]
                        });
                        return val;
                    }, [])
                });

                return arr;
            }, [])
        });
    }

    /**
     * @Route("/firewall", methods=['GET'])
     */
    firewall(req, res) {
        const config = this.getSecurityConfig();
        const firewall = config.firewall;
        const keys = Object.keys(firewall);
        return Promise.resolve({
            total: keys.length,
            firewalls: keys.reduce((arr, key) => {
                let auth = firewall[key].authenticator;
                let authKey = auth instanceof Object ? auth.id || auth.service : auth;
                let roles = firewall[key].roles || [];
                if (!Array.isArray(roles)) {
                    roles = [roles];
                }
                arr.push({
                    id: key,
                    route: firewall[key].route,
                    anonymous: firewall[key].anonymous === true,
                    roles: roles,
                    stateless: firewall[key].stateless,
                    shared: firewall[key].shared,
                    routes: firewall[key].routes,
                    encryption: firewall[key].encryption,
                    provider: firewall[key].provider,
                    authenticator: {
                        key: authKey,
                        options: (auth instanceof Object && auth.options) || undefined
                    }
                });
                return arr;
            }, [])
        });
    }

    /**
     * @Route("/authenticators", methods=['GET'])
     */
    authenticators(req, res) {
        const config = this.getSecurityConfig();
        const firewall = config.firewall;
        const auth = config.authenticators;
        const keys = Object.keys(auth);
        const firewallKeys = Object.keys(firewall);
        return Promise.resolve({
            total: keys.length,
            authenticators: keys.reduce((arr, key) => {
                arr.push({
                    id: key,
                    service: auth[key],
                    firewalls: firewallKeys.reduce((arr, firewallKey) => {
                        const node = firewall[firewallKey];
                        if (node.authenticator === key) {
                            arr.push(firewallKey);
                            return arr;
                        }
                        if (node.authenticator instanceof Object) {
                            if (node.authenticator.id === key ||
                                node.authenticator.service === key ||
                                node.authenticator.service === auth[key]
                            ) {
                                arr.push(firewallKey);
                            }
                        }
                        return arr;
                    }, [])
                });
                return arr;
            }, [])
        });
    }

    /**
     * @Route("/providers", methods=['GET'])
     */
    providers(req, res) {
        const config = this.getSecurityConfig();
        const firewall = config.firewall;
        const providers = config.providers;
        const keys = Object.keys(providers);
        const firewallKeys = Object.keys(firewall);
        return Promise.resolve({
            total: keys.length,
            providers: keys.reduce((arr, key) => {
                let type = 'Custom';
                const provider = providers[key];
                let value = provider;
                if (typeof provider === 'string') {
                    type = 'Service';
                } else if (Array.isArray(provider)) {
                    type = 'Chain';
                    value = provider.join('\n');
                } else if (provider instanceof Object) {
                    const keys = Object.keys(provider);
                    if (keys.length === 1) {
                        type = keys[0][0].toUpperCase() + keys[0].substr(1).toLowerCase();
                    }
                    value = JSON.stringify(provider, null, 4);
                }
                arr.push({
                    id: key,
                    type: type,
                    value: value,
                    firewalls: firewallKeys.reduce((arr, firewallKey) => {
                        const firewallProvider = firewall[firewallKey].provider;
                        if (firewallProvider === key) {
                            arr.push(firewallKey);
                        } else {
                            // look for firewalls that have chains
                            if (Array.isArray(providers[firewallProvider]) &&
                                providers[firewallProvider].indexOf(key) !== -1
                            ) {
                                arr.push(firewallKey);
                            }
                        }
                        return arr;
                    }, [])
                });
                return arr;
            }, [])
        });
    }
}

module.exports = SecurityController;