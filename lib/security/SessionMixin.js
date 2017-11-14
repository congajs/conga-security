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

    get(name, defaultValue = null) {
        if (name[0] === '_') {
            return defaultValue;
        }
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.getSecurityContext(realm);
            if (context && name in context.data) {
                return context.data[name];
            }
        }
        if (name in this) {
            return this[name];
        }
        return defaultValue;
    },

    set(name, value) {
        if (name[0] === '_' || value instanceof Function) {
            return null;
        }
        const realm = this.getCurrentRealm();
        if (!realm || name in this) {
            this[name] = value;
        } else if (realm) {
            const context = this.getSecurityContext(realm);
            if (!context) {
                return null;
            }
            context.data[name] = value;
        }
        return value;
    },

    has(name) {
        if (name[0] === '_') {
            return false;
        }
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.getSecurityContext(realm);
            return context && !(context.data[name] instanceof Function);
        }
        return name in this && !(this[name] instanceof Function);
    },

    keys() {
        let keys = [];
        const realm = this.getCurrentRealm();
        const context = this.getSecurityContext(realm);
        if (realm && context) {
            keys = keys.concat(Object.keys(context.data).filter(key => {
                return key[0] !== '_' && !(context.data[key] instanceof Function);
            }));
        }
        return keys.concat(Object.keys(this).filter(key => (
            key[0] !== '_' &&
            !(this[key] instanceof Function)) &&
            (!context || !(key in context.data))
        ));
    },

    delete(name) {
        if (name[0] === '_') {
            return false;
        }
        let bool = false;
        const realm = this.getCurrentRealm();
        if (realm) {
            const context = this.getSecurityContext(realm);
            if (context && name in context.data) {
                delete context.data[name];
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

    data() {
        return this.keys().reduce((data, key) => {
            data[key] = this.get(key);
            return data;
        }, {});
    },

    /*
       NOTE: we don't overwrite the iterator because iterator is a built in mixin and does it by
       default - if the user wants to disable iterator, then they won't also have to disable the
       session mixin
     */

    /** security context **/

    /**
     * Initialize the security context object
     * @returns {{realms: {}, currentRealm: {String}}}
     */
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
        return this.__securityContext && this.__securityContext.currentRealm;
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
        if (!this.__securityContext) {
            return [];
        }
        const context = this.initSecurityContext();
        return Object.keys(context.realms);
    },

    /**
     * See if a security has previously been saved
     * @param {String} realm The security realm to check for
     * @returns {boolean}
     */
    hasSecurityContext(realm) {
        return this.__securityContext && realm in this.__securityContext.realms;
    },

    /**
     * Get the saved security context by realm
     * @param {String} realm The security realm to check for
     * @returns {{token:{String}, data:{Object}}|null}
     */
    getSecurityContext(realm) {
        if (!this.__securityContext) {
            return null;
        }
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
            context.realms[realm] = Object.assign({token, realm, data: {}}, context.realms[realm]);
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