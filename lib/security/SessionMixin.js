/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Mixin for the security context with @conga/session-framework
 * @type {Object}
 */
const SessionMixin = {

    /** overload iterator - anything set inside a security realm
            gets saved in that realm's session data **/

    get(name) {
        if (name[0] === '_') {
            return null;
        }
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.initSecurityContext();
            if (name in context.realms[realm].data) {
                return context.realms[realm].data[name];
            }
        }
        return this[name];
    },

    set(name, value) {
        if (name[0] === '_' || value instanceof Function) {
            return null;
        }
        const realm = this.getCurrentRealm();
        if (!realm || name in this) {
            this[name] = this;
        } else if (realm) {
            const context = this.initSecurityContext();
            context.realms[realm].data[name] = value;
        }
        return value;
    },

    has(name) {
        if (name[0] === '_') {
            return false;
        }
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.initSecurityContext();
            if (realm in context.realms) {
                return !(context.realms[realm].data[name] instanceof Function);
            }
        }
        return name in this && !(this[name] instanceof Function);
    },

    keys() {
        let keys = [];
        const realm = this.getCurrentRealm();
        const context = this.initSecurityContext();
        if (realm) {
            keys = keys.concat(Object.keys(context.realms[realm].data).filter(key => {
                return key[0] !== '_' && !(context.realms[realm].data[key] instanceof Function);
            }));
        }
        keys = keys.concat(Object.keys(this).filter(key => {
            return !(key in context.realms[realm].data) &&
                   key[0] !== '_' &&
                   !(this[key] instanceof Function);
        }));
        return keys;
    },

    delete(name) {
        if (name[0] === '_') {
            return false;
        }
        let bool = false;
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.initSecurityContext();
            if (name in context.realms[realm].data) {
                delete context.realms[realm].data[name];
                bool = true;
            }
        }
        if (name in this && !(this[name] instanceof Function)) {
            delete this[name];
            bool = true;
        }
        return bool;
    },

    entries() {
        return this.keys().map(key => [key, this[key]]);
    },

    values() {
        return this.keys().map(key => this[key]);
    },

    /*
       NOTE: we don't overwrite the iterator because iterator is a built in mixin and does it by
       default - if the user wants to disable iterator, then they won't also have to disable the
       session mixin
     */

    /** security context **/

    initSecurityContext() {
        if (!this.__securityContext) {
            this.__securityContext = {realms: {}, currentRealm: null};
        }
        return this.__securityContext;
    },

    /**
     * Get the current security realm
     * @returns {String}
     */
    getCurrentRealm() {
        return this.initSecurityContext().currentRealm;
    },

    /**
     * Set the current security realm
     * @param {String} realm
     * @returns {void}
     */
    setCurrentRealm(realm) {
        const context = this.initSecurityContext();
        if (realm && !(realm in context.realms)) {
            context.realms[realm] = {token: null, realm, data: {}};
        }
        context.currentRealm = realm;
    },

    /**
     * Get all the known security realms
     * @returns {Array}
     */
    getSecurityRealms() {
        const context = this.initSecurityContext();
        return Object.keys(context.realms);
    },

    /**
     * See if a security has previously been saved
     * @param {String} realm The security realm to check for
     * @returns {boolean}
     */
    hasSecurityContext(realm) {
        const context = this.initSecurityContext();
        return realm in context.realms;
    },

    /**
     * Get the saved security context by realm
     * @param {String} realm The security realm to check for
     * @returns {{token:{String}, data:{Object}}|null}
     */
    getSecurityContext(realm) {
        const context = this.initSecurityContext();
        return context.realms[realm];
    },

    /**
     * Set a security context / save a token (also changes the current security realm)
     * @param {String} realm The security realm the token belongs to
     * @param {EncryptedAuthToken} token The encrypted auth token to save
     * @returns {void}
     */
    setSecurityContext(realm, token) {
        const context = this.initSecurityContext();
        if (realm in context.realms) {
            if (!context.realms[realm].token) {
                context.realms[realm].token = token;
            }
            context.realms[realm].realm = realm;
        } else {
            context.realms[realm] = {token, realm, data: {}};
        }
        this.setCurrentRealm(realm);
    },

    /**
     * Delete a security realm previously saved
     * @param {String} realm
     * @returns {boolean}
     */
    deleteSecurityContext(realm) {
        const context = this.initSecurityContext();
        if (realm in context.realms) {
            delete context.realms[realm];
            if (Object.keys(context.realms).length === 0) {
                this.__securityContext = null;
                delete this.__securityContext;
            } else if (realm === this.getCurrentRealm()) {
                this.setCurrentRealm(null);
            }
            return true;
        }
        return false;
    }

};

module.exports = () => SessionMixin;