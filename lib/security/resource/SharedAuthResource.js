/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthResourceProxy = require('./AuthResourceProxy');

/**
 * Array of known fields available to use
 * @type {Object}
 */
const FIELDS = [
    'id','email','username','login','createdAt','updatedAt','version',
    'name','firstName','lastName','address','city','state','zip','phone'
].reduce((obj, name) => {
    obj[name] = 1;
    return obj;
}, {});

/**
 * A shared authenticated resource (user, api client, etc)
 */
class SharedAuthResource extends AuthResourceProxy {
    /**
     * Get the default proxied fields hash
     * @returns {Object}
     * @constructor
     */
    static get FIELDS() {
        return FIELDS;
    }

    /**
     *
     * @param {Object} resource the resource to proxy
     * @param {Object} [fields] hash of proxied fields (optional)
     */
    constructor(resource, fields = null) {
        super(resource, fields);
    }
}

module.exports = SharedAuthResource;