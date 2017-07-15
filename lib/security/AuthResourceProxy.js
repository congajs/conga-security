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
     * @param {Object} resource
     */
    constructor(resource) {
        super(resource.roles || []);
        this._resource = resource;
        this.wrap(resource);
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
     * @param {Object} obj
     */
    wrap(obj) {
        if (!obj || !(obj instanceof Object)) {
            return;
        }
        Object.keys(obj).concat(Object.getOwnPropertyNames(Object.getPrototypeOf(obj))).forEach(property => {
            if (this[property] === undefined) {
                this.__defineGetter__(property, () => obj[property]);
            }
        });
    }
}

module.exports = AuthResourceProxy;