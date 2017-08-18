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
const FirewallProcessor = require('./FirewallProcessor');
const AnonAuthToken = require('./../token/AnonAuthToken');
const EncryptedAuthToken = require('./../token/EncryptedAuthToken');

/**
 * The SessionFirewallProcess processes a request through a firewall but also considers
 * tokens stored in the user's session if the request payload doesn't contain the
 * authentication credentials
 */
class SessionFirewallProcessor extends FirewallProcessor {

    /**
     * {@inheritDoc}
     * @see FirewallProcessor.constructor
     */
    constructor(request, firewall) {
        super(...arguments);

        const realmBuff = Buffer.from(this.realm);
        this.sessions = [this.realm].concat(this.request.session.getSecurityRealms()
            .filter(val => this.realm.length !== val.length &&
                           !crypto.timingSafeEqual(Buffer.from(val), realmBuff)));

        this.encryptSalt = this.firewall.encryption_salt || '';
        this.encryptAlgo = this.firewall.encryption_algorithm;

        if (this.encryptSalt instanceof Function) {
            this.encryptSalt = this.encryptSalt(this.firewall) || '';
        }

        if (this.encryptAlgo instanceof Function) {
            this.encryptAlgo = this.encryptAlgo(this.firewall);
        }

        if (!this.encryptAlgo) {
            this.encryptAlgo = EncryptedAuthToken.DEFAULT_ALGORITHM;
        }
    }

    /**
     * Set the firewall service on this processor
     * @param {FirewallFactory} factory The firewall factory service
     * @returns {void}
     */
    setFirewallFactory(factory) {
        this.firewallFactory = factory;
    }

    /**
     * Set the provider factory on this processor
     * @param {ProviderFactory} factory The provider factory servie
     * @returns {void}
     */
    setProviderFactory(factory) {
        this.providerFactory = factory;
    }

    /**
     * {@inheritDoc}
     * @see FirewallProcessor.getPreAuthToken
     */
    getPreAuthToken() {

        return super.getPreAuthToken().then(token => {

            if (token && !(token instanceof AnonAuthToken)) {
                return token;
            }

            return this.getSessionAuthToken();

        }).catch(err => {

            return this.getSessionAuthToken().catch(() => {
                // reject with the original error
                return Promise.reject(err);
            });
        });
    }

    /**
     * Get an auth token through the session
     * @param {Array} [sessions] The sessions to iterate over (if not given, this.sessions is used)
     * @returns {Promise.<AuthToken>}
     */
    getSessionAuthToken(sessions) {
        let config, session, sessionRealm;

        if (!Array.isArray(sessions)) {
            sessions = this.sessions.slice();
        }

        while (!config && (sessionRealm = sessions.shift())) {
            session = this.request.session.getSecurityContext(sessionRealm);
            if (session && session.token && session.realm) {
                config = this.firewallFactory.getFirewallConfigForRealm(session.realm);
            }
        }

        if (!config) {
            return Promise.resolve(null);
        }

        const provider = this.providerFactory.getFirewallProvider(config);

        let encryptSalt = config.encryption_salt || '';
        let encryptAlgo = config.encryption_algorithm;

        if (encryptSalt instanceof Function) {
            encryptSalt = encryptSalt(config) || '';
        }

        if (encryptAlgo instanceof Function) {
            encryptAlgo = encryptAlgo(config);
        }

        if (!encryptAlgo) {
            encryptAlgo = EncryptedAuthToken.DEFAULT_ALGORITHM;
        }

        let token = EncryptedAuthToken.decrypt(session.token, encryptSalt, encryptAlgo);

        if (!token) {
            return this.getSessionAuthToken(sessions);
        }

        if (!this.authenticator || !provider) {
            if (this.constructor.validate(this.roles, token.roles || [])) {
                return Promise.resolve(token);
            }
            return this.getSessionAuthToken(sessions);
        }

        if (!this.authenticator.supportsToken(token, session.realm)) {
            return this.getSessionAuthToken(sessions);
        }

        return this.authenticator.refreshToken(token, provider, session.realm).then(token => {
            if (token &&
                this.constructor.validateRoles(this.roles, token.roles || [])
            ) {
                return token;
            }
            return this.getSessionAuthToken(sessions);
        }).catch(err => this.getSessionAuthToken(sessions));
    }

    /**
     * {@inheritDoc}
     * @see FirewallProcessor.process
     */
    process() {

        return super.process().then(authToken => {

            if (authToken.stateless) {
                // if the token is stateless, remove it from the session if it exists
                // but if it's anonymous we don't want to delete any existing session
                if (!(authToken instanceof AnonAuthToken)) {
                    this.request.session.deleteSecurityContext(this.realm);
                }
            } else {
                // if the firewall and token are stateful, save the token in the session
                this.request.session.setSecurityContext(
                    this.realm,
                    new EncryptedAuthToken(
                        authToken,
                        this.encryptSalt,
                        authToken.encrypted,
                        this.encryptAlgo
                    )
                );
            }

            return authToken;

        }).catch(err => {

            this.request.session.deleteSecurityContext(this.realm);
            return Promise.reject(err);
        });
    }

}

module.exports = SessionFirewallProcessor;