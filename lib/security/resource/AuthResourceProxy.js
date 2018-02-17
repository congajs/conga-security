/*
 * This file is part of the conga-security library.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthResource = require('./AuthResource');

/**
 * The auth resource proxy wraps another instance
 */
class AuthResourceProxy extends AuthResource {
    /**
     *
     * @param {Object} resource the resource to proxy
     * @param {Object} [fields] hash of proxied fields (optional)
     */
    constructor(resource, fields = null) {
        super(resource.roles || []);
        Object.defineProperty(this, '_resource', {
            value: resource,
            writable: false,
            configurable: false,
            enumerable: false
        });
        this.wrap(resource, fields);
    }

    /**
     * Get the underlying resource
     * @returns {Object}
     */
    getResource() {
        return this._resource;
    }

    /**
     * Wrap this object around another object
     * @param {Object} obj the object to wrap
     * @param {Object} [fields] hash of proxied fields (optional)
     */
    wrap(obj, fields = null) {
        if (!obj || !(obj instanceof Object)) {
            return;
        }
        Object.keys(obj).concat(Object.getOwnPropertyNames(Object.getPrototypeOf(obj))).forEach(property => {
            if (property[0] !== '_' &&
                this[property] === undefined &&
                (!fields || fields[property])
            ) {
                this.__defineGetter__(property, () => obj[property]);
            }
        });
    }
}

module.exports = AuthResourceProxy;