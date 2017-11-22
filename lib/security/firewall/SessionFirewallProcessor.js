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
const EncryptedAuthToken = require('./../token/EncryptedAuthToken');
const SharedAuthToken = require('./../token/SharedAuthToken');
const SecurityError = require('./../../error/SecurityError');
const HttpError = require('./../../error/HttpError');

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

        // sessions have their tokens encrypted, resolve the salt and algorithm to use

        const encrypt = this.firewall.encryption || {};

        this.encryptSalt = encrypt.salt || '';
        this.encryptAlgo = encrypt.algorithm;

        if (this.encryptSalt instanceof Function) {
            this.encryptSalt = this.encryptSalt(this.firewall) || '';
        }

        if (this.encryptAlgo instanceof Function) {
            this.encryptAlgo = this.encryptAlgo(this.firewall);
        }

        if (!this.encryptAlgo) {
            this.encryptAlgo = EncryptedAuthToken.DEFAULT_ALGORITHM;
        }

        /* NOTE: Some firewalls don't allow any or only allow some other realms. We need to
                 get a collection of supported realms from the session. These session realms
                 will be used to find, decrypt, and validate encoded tokens for reuse. */

        this.sessions = [];

        let shared = this.firewall.shared;
        if (!Array.isArray(shared)) {
            shared = !!shared;
        }
        if (shared) {
            const realmBuff = Buffer.from(this.realm);
            this.sessions = this.request.session.getSecurityRealms().filter(securityRealm => {
                const securityRealmBuff = Buffer.from(securityRealm);

                // if the realm is not this realm (we move this realm to the top)
                if (this.realm.length === securityRealm.length &&
                    crypto.timingSafeEqual(securityRealmBuff, realmBuff)
                ) {
                    return false;
                }

                // if all realms are supported
                if (shared === true) {
                    return true;
                }

                // if this realm, specifically, is supported
                let bool = false;
                for (let check of shared) {
                    if (check.length === securityRealm.length) {
                        bool = crypto.timingSafeEqual(Buffer.from(check), securityRealmBuff);
                    }
                }

                return bool;
            });
        }

        // always add this realm to the top of the session realms
        this.sessions.unshift(this.realm);
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
        return new Promise((resolve, reject) => {

            // if a pre-auth token isn't resolved normally, check supported session realms
            super.getPreAuthToken().then(token => {

                if (token && !token.anonymous) {
                    resolve(token);
                    return;
                }

                const stopwatch = this.stopwatch &&
                    this.stopwatch.start('firewall.session', 'security');

                this.getSessionAuthToken().then(preAuthToken => {
                    stopwatch && stopwatch.stop();
                    resolve(preAuthToken);
                }).catch(err => {
                    // if the token was anonymous before we attempted to find a session token,
                    // and since we failed, use the anonymous token
                    if (token.anonymous) {
                        stopwatch && stopwatch.stop();
                        resolve(token);
                        return;
                    }
                    // pass the error through the rejection chain
                    stopwatch && stopwatch.stop();
                    reject(new HttpError(err.message, err.status || 500, err));
                });

            }).catch(err => {

                const stopwatch = this.stopwatch &&
                    this.stopwatch.start('firewall.session', 'security');

                this.getSessionAuthToken().then(preAuthToken => {
                    stopwatch && stopwatch.stop();
                    resolve(preAuthToken);
                }).catch(() => {
                    // reject with the original error
                    stopwatch && stopwatch.stop();
                    reject(new HttpError(err.message, err.status || 500, err));
                });
            });
        });
    }

    /**
     * Get an auth token through the session
     * @param {Array} [sessions] The sessions to iterate over (if not given, this.sessions is used)
     * @returns {Promise.<AuthToken>}
     */
    getSessionAuthToken(sessions = null) {
        let config, session, sessionRealm;

        // initialize the sessions array if it's not provided
        if (!Array.isArray(sessions)) {
            sessions = this.sessions.slice();
        }

        // get the next session realm from the top of the sessions queue
        while (!config && (sessionRealm = sessions.shift())) {
            session = this.request.session.getSecurityContext(sessionRealm);
            if (session && session.token && session.realm) {
                config = this.firewallFactory.getFirewallConfigForRealm(session.realm);
            }
        }

        // if a config object can't be mapped, we are done checking all available realms - fail
        if (!config) {
            return Promise.reject(new SecurityError('Session auth token not found'));
        }

        /* if we get here it means we found a security context in the session that should be
            checked for validation */

        // use the provider on the firewall config for the session realm we are checking
        const provider = this.providerFactory.getFirewallProvider(config);

        // use the encryption settings on the firewall config for the session realm we are checking
        const encrypt = config.encryption || {};
        let encryptSalt = encrypt.salt || '';
        let encryptAlgo = encrypt.algorithm;

        if (encryptSalt instanceof Function) {
            encryptSalt = encryptSalt(config.authenticator) || '';
        }

        if (encryptAlgo instanceof Function) {
            encryptAlgo = encryptAlgo(config.authenticator);
        }

        if (!encryptAlgo) {
            encryptAlgo = EncryptedAuthToken.DEFAULT_ALGORITHM;
        }

        // decrypt the encrypted token and get an fresh AuthToken
        let token = EncryptedAuthToken.decrypt(
            session.token,
            encryptSalt,
            encryptAlgo,
            session.token.realm
        );

        // if the token can't be decrypted, see if we can find another one
        if (!token) {
            return this.getSessionAuthToken(sessions);
        }

        const isRealm = FirewallProcessor.compare(token.realm, this.realm);

        if (token.shared) {
            // if the token is shared, and it's not this realm, try for another
            if (!isRealm) {
                return this.getSessionAuthToken(sessions);
            }
            // make sure the shared token still exists, otherwise that means the user logged out
            // or the session expired, either way it's invalid
            const context = this.request.session.getSecurityContext(token.sharedRealm);
            if (!context) {
                this.request.session.deleteSecurityContext(this.realm);
                return this.getSessionAuthToken(sessions);
            }
        }

        // if we are dealing with a simple firewall rule, don't refresh
        if (!this.authenticator || !provider) {
            if (this.validateRoles(token.roles)) {
                return Promise.resolve(isRealm ? token : new SharedAuthToken(token, this.realm));
            }
            return this.getSessionAuthToken(sessions);
        }

        // NOTE: we are using this firewall's authenticator, not the session's

        // make sure the authenticator supports the token
        if (!this.authenticator.supportsToken(token, session.realm)) {
            return this.getSessionAuthToken(sessions);
        }

        // refresh the token for this realm, using the configured provider on the session's realm
        return this.authenticator.refreshToken(token, provider, this.realm).then(refreshed => {

            // validate the token roles to make sure the token has access to this firewall realm
            if (refreshed && this.validateRoles(refreshed.roles)) {
                if (isRealm) {
                    return refreshed;
                }
                return new SharedAuthToken(
                    refreshed,
                    refreshed.realm,
                    token.sharedFields,
                    token.sharedRealm || token.realm
                );
            }

            // if the token doesn't validate, check the next one
            return this.getSessionAuthToken(sessions);

        }).catch(err => this.getSessionAuthToken(sessions));
    }

    /**
     * {@inheritDoc}
     * @see FirewallProcessor.process
     */
    process() {
        return new Promise((resolve, reject) => {

            super.process().then(authToken => {

                const stopwatch = this.stopwatch &&
                    this.stopwatch.start('firewall.session', 'security');

                if (authToken && !authToken.stateless) {
                    let sessionToken = authToken;
                    if (sessionToken.redirect) {
                        sessionToken = sessionToken.getSourceToken();
                    }
                    // if we got a valid token, and if it's stateful, save it in the session
                    this.request.session.setSecurityContext(
                        this.realm,
                        new EncryptedAuthToken(
                            sessionToken,
                            this.encryptSalt,
                            sessionToken.encrypted,
                            this.encryptAlgo
                        )
                    );
                } else if (!authToken || !authToken.anonymous) {
                    /* if we don't have a token, or if it's stateless, remove it from the session,
                        but if it's anonymous we don't want to delete any existing session */
                    this.request.session.deleteSecurityContext(this.realm);
                }

                // we want to make sure the session is persisted before any redirect happens
                this.request.session.save(saveErr => {
                    if (saveErr) {
                        console.error('session.save', saveErr.stack || saveErr);
                    }
                    if (!authToken) {
                        // if we did not get a token, fail
                        stopwatch && stopwatch.stop();
                        reject(new SecurityError('Session auth token not found'));
                    } else {
                        stopwatch && stopwatch.stop();
                        resolve(authToken);
                    }
                });
            }).catch(err => this.processCatcher(err)).catch(reject);
        });
    }

    /**
     * {@inheritDoc}
     * @see FirewallProcessor.processCatcher
     */
    processCatcher(err) {
        // clear out the session realm on any Unauthorized or Forbidden HTTP error (401, 402, 403) status
        // if it's a server error, don't clear the session
        if (err.status) {
            const status = Math.max(err.status, err.previous && err.previous.status);
            // check the status code of the error
            if (status < 500) {
                this.request.session.deleteSecurityContext(this.realm);
            }
        }
        // we want to make sure the session is persisted before any redirect happens
        return new Promise((resolve, reject) => {
            this.request.session.save(saveErr => {
                if (saveErr) {
                    console.error('session.save', saveErr.stack || saveErr);
                }
                super.processCatcher(err).then(resolve).catch(reject);
            });
        });
    }

}

module.exports = SessionFirewallProcessor;