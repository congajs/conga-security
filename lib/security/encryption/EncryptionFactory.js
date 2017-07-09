/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractEncryptor = require('./AbstractEncryptor');
const InvalidArgumentError = require('./../../error/InvalidArgumentError');
const LogicError = require('./../../error/LogicError');

/**
 * The name of the prototype field used to map encoders
 * @type {string}
 */
const MAPPED_PROTO = '_CONGA_SECURITY_ENCODER';

/**
 * Mapped encryption algorithms
 * @type {Object}
 */
const algorithms = {};

/**
 * The encryption factory is responsible for keeping track of encryptors and mapped resources
 */
class EncryptionFactory {
    /**
     * @param {Object} container The service container
     */
    constructor(container) {
        this.container = container;
    }

    /**
     * See if an algorithm is registered
     * @param {String} algo The encryption algorithm to check for
     * @returns {boolean}
     */
    isRegisteredAlgorithm(algo) {
        return algo in algorithms;
    }

    /**
     * Register an encryption algorithm
     * @param {String} algo The algorithm name this encryptor is recognized as
     * @param {AbstractEncryptor|{encrypt:{Function}, compare:{Function}}} encryptor The encryptor to register
     * @returns {void}
     * @throws LogicError for registering an algorithm more than once
     * @throws InvalidArgumentError for providing an encryptor that does not support the abstract methods
     */
    registerAlgorithm(algo, encryptor) {
        if (this.isRegisteredAlgorithm(algo)) {
            throw new LogicError('You cannot register an algorithm more than once, "' + algo + '".');
        }
        if (!(encryptor instanceof AbstractEncryptor) &&
            (typeof encryptor.encrypt !== 'function' || typeof encryptor.compare !== 'function')
        ) {
            throw new InvalidArgumentError(
                'Your security encryptor must implement the abstract methods, "encrypt" and "compare".');
        }
        algorithms[algo] = encryptor;
    }

    /**
     * Unregister an encryption algorithm
     * @param {String} algo The encryption algorithm to unregister
     * @returns {void}
     */
    unregisterAlgorithm(algo) {
        if (this.isRegisteredAlgorithm(algo)) {
            algorithms[algo] = null;
            delete algorithms[algo];
        }
    }

    /**
     * Get an encryptor for a specific encryption algorithm
     * @param {String} algo The encryption algorithm
     * @returns {AbstractEncryptor|{encrypt:{Function}, compare:{Function}}|null}
     */
    getEncryptorForAlgorithm(algo) {
        if (!this.isRegisteredAlgorithm(algo)) {
            return null;
        }
        return algorithms[algo];
    }

    /**
     * Get a security encryptor from a configuration object
     * @param {Object} config The configuration object
     * @returns {AbstractEncryptor|{encrypt:{Function}, compare:{Function}}|null}
     * @throws LogicError when the resolved encryptor does not support the abstract methods
     */
    getEncryptorForConfig(config) {
        if (!(config instanceof Object)) {
            throw new InvalidArgumentError('Invalid configuration object provided.');
        }

        if (config.algorithm) {
            return this.getEncryptorForAlgorithm(config.algorithm);
        }

        let encryptor;

        if (!encryptor && config.id && this.container.has(config.id)) {
            encryptor = this.container.get(config.id);
        }

        if (encryptor instanceof Object) {
            if (!(encryptor instanceof AbstractEncryptor) &&
                (typeof encryptor.encrypt !== 'function' || typeof encryptor.compare !== 'function')
            ) {
                throw new InvalidArgumentError(
                    'Your security encryptor must implement the abstract methods, "encrypt" and "compare".');
            }
            return encryptor;
        }

        return null;
    }

    /**
     * Get the prototype object of a resource class (not instance)
     * @param {Object|Function} resource Any mapped resource
     * @returns {Object}
     * @throws InvalidArgumentError for invalid resource provided
     */
    getPrototypeOfClass(resource) {
        if (typeof resource === 'function') {
            return resource.prototype;
        }
        return Object.getPrototypeOf(resource);
    }

    /**
     * See if a given resource is a mapped encoder
     * @param {Object} resource Any object
     * @param {Object} [proto] The prototype object reference, if you already have it
     * @returns {boolean}
     */
    isMapped(resource, proto = null) {
        if (!(proto instanceof Object)) {
            proto = this.getPrototypeOfClass(resource);
        }
        return proto && MAPPED_PROTO in proto;
    }

    /**
     * Get a mapped encryptor for a given resource
     * @param {Object} resource Any mapped object
     * @param {Object} [proto] The prototype object reference, if you already have it
     * @returns {AbstractEncryptor|{encrypt:{Function}, compare:{Function}}|null}
     */
    getMappedEncryptor(resource, proto = null) {
        if (!(proto instanceof Object)) {
            proto = this.getPrototypeOfClass(resource);
        }
        return proto[MAPPED_PROTO] && proto[MAPPED_PROTO].encryptor || null;
    }

    /**
     * Get a mapped security encryption configuration object for a given resource
     * @param {Object} resource Any mapped object
     * @param {Object} [proto] The prototype object reference, if you already have it
     * @returns {Object|null}
     */
    getMappedConfig(resource, proto = null) {
        if (!(proto instanceof Object)) {
            proto = this.getPrototypeOfClass(resource);
        }
        return proto[MAPPED_PROTO] && proto[MAPPED_PROTO].config || null;
    }

    /**
     * Map an encryptor to a resource
     * @param {Object} resource Any object
     * @param {AbstractEncryptor|Object|*} encryptor The encryptor to map to the resource
     * @param {Object} config The configuration object for this defined encryption resource
     * @returns {void}
     * @throws InvalidArgumentError for providing an encryptor that does not support the abstract methods
     * @throws LogicError for trying to map an already mapped resource
     */
    mapResource(resource, encryptor, config) {
        if (!(encryptor instanceof AbstractEncryptor) &&
            (typeof encryptor.encrypt !== 'function' || typeof encryptor.compare !== 'function')
        ) {
            throw new InvalidArgumentError(
                'Your security encryptor must implement the abstract methods, "encrypt" and "compare".');
        }

        const proto = this.getPrototypeOfClass(resource);

        if (!proto) {
            return;
        }

        if (this.isMapped(resource, proto)) {
            if (proto[MAPPED_PROTO].encryptor !== encryptor) {
                throw new LogicError('You cannot change an encryptor-resource mapping once it is defined.');
            }
            return;
        }

        proto[MAPPED_PROTO] = {encryptor, config};
    }

    /**
     * Remove an encryptor mapping from a resource
     * @param {Object} resource Any mapped object
     * @returns {void}
     */
    unmapResource(resource) {
        const proto = this.getPrototypeOfClass(resource);
        if (MAPPED_PROTO in proto) {
            proto[MAPPED_PROTO] = null;
            delete proto[MAPPED_PROTO];
        }
    }
}

module.exports = EncryptionFactory;