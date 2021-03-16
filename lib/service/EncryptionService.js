/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const SecurityError = require('./../error/SecurityError');
const LogicError = require('./../error/LogicError');
const EncryptionFactory = require('./../security/encryption/EncryptionFactory');

/**
 * The encryption factory
 * @type {EncryptionFactory}
 */
let factory;

/**
 * The encryption service helps with encrypting data for mapped resources and known algorithms
 */
class EncryptionService {
    /**
     * @param {Object} container The service container
     */
    constructor(container) {
        if (!factory) {
            factory = new EncryptionFactory(container);
        }
    }

    /**
     * {@see EncryptionFactory.isRegisteredAlgorithm}
     */
    isRegisteredAlgorithm(algo) {
        return factory.isRegisteredAlgorithm(algo);
    }

    /**
     * {@see EncryptionFactory.registerAlgorithm}
     */
    registerAlgorithm(algo, encryptor) {
        return factory.registerAlgorithm(algo, encryptor);
    }

    /**
     * {@see EncryptionFactory.unregisterAlgorithm}
     */
    unregisterAlgorithm(algo) {
        return factory.unregisterAlgorithm(algo);
    }

    /**
     * {@see EncryptionFactory.getEncryptorForAlgorithm}
     */
    getEncryptorForAlgorithm(algo) {
        return factory.getEncryptorForAlgorithm(algo);
    }

    /**
     * {@see EncryptionFactory.getEncryptorForConfig}
     */
    getEncryptorForConfig(config) {
        return factory.getEncryptorForConfig(config);
    }

    /**
     * {@see EncryptionFactory.isMapped}
     */
    isMapped(resource) {
        return factory.isMapped(resource);
    }

    /**
     * {@see EncryptionFactory.getMappedEncryptor}
     */
    getMappedEncryptor(resource) {
        return factory.getMappedEncryptor(resource);
    }

    /**
     * {@see EncryptionFactory.mapResource}
     */
    mapResource(resource, encoder, config) {
        return factory.mapResource(resource, encoder, config);
    }

    /**
     * {@see EncryptionFactory.unmapResource}
     */
    unmapResource(resource) {
        return factory.unmapResource(resource);
    }

    /**
     * Parse common configuration directives and options
     * @param {*} resource Any mapped resource
     * @param {Object} config The configuration object for this defined encryption resource
     * @returns {Object} The (manipulated) config object
     */
    parseConfig(resource, config) {
        if (config instanceof Object) {
            if (config.fields) {
                for (let key in config.fields) {
                    config.fields[key] = resource[ config.fields[key] ];
                }
            }
            if (config.methods) {
                if (!config.fields) {
                    config.fields = {};
                }
                for (let key in config.methods) {
                    if (typeof resource[ config.methods[key] ] === 'function') {

                        // NOTE: methods, overwrite fields from the method return value
                        config.fields[key] = resource[ config.methods[key] ].call(resource);

                    }
                }
            }
        }
        return config;
    }

    /**
     * Prepare the string for encryption by applying salt, pepper, etc
     * @param {String} str The string to encrypt
     * @param {Object} config The configuration object for this defined encryption resource
     * @returns {String}
     */
    prepareStringForEncryption(str, config) {
        if (!(config instanceof Object)) {
            return str;
        }

        if (config.fields && config.fields.salt) {
            str = config.fields.salt + str;
        } else if (config.salt) {
            str = config.salt + str;
        }

        if (config.pepper) {
            str = config.pepper + str;
        }

        return str;
    }

    /**
     * Compare a plain text string to an encrypted string to see if they are the same
     * @param {*} resource Any mapped resource
     * @param {String} str The string to encrypt
     * @param {String} encrypted The encrypted string you are comparing
     * @returns {Promise} a promise that resolves a boolean
     */
    compare(resource, str, encrypted) {

        let stopwatch = factory.container.has('profiler.stopwatch') &&
                        factory.container.get('profiler.stopwatch').start('encryption.compare', 'security');

        const proto = factory.getPrototypeOfClass(resource);

        if (!factory.isMapped(resource, proto)) {
            throw new LogicError('The provided resource has not been mapped to an encryptor. Unable to compare.');
        }

        const encryptor = factory.getMappedEncryptor(resource, proto);

        if (!(encryptor instanceof Object)) {
            throw new SecurityError(
                'The mapped encryptor for the given resource could not be found. Unable to compare.');
        }

        const config = this.parseConfig(resource, factory.getMappedConfig(resource, proto) || {});

        str = this.prepareStringForEncryption(str, config);

        if (config.encode_as_base64) {
            // base64 decode the encrypted string first, when configured as such
            encrypted = (Buffer.from(encrypted, 'base64')).toString('ascii');
        }

        stopwatch && stopwatch.stop();

        return encryptor.compare(str, encrypted, config);
    }

    /**
     * Encode a given string for a given resource - if the resource is not mapped, the str is resolved as is
     * @param {*} resource Any mapped resource
     * @param {String} str The string to encode
     * @returns {Promise} a promise that resolves a string
     * @throws SecurityError for not being able to find an encoder for a mapped resource
     * @throws LogicError for getting an encoder that does not inherit from AbstractEncoder or have an encode method
     */
    encrypt(resource, str) {
        let stopwatch = factory.container.has('profiler.stopwatch') &&
                        factory.container.get('profiler.stopwatch').start('encryption.encrypt', 'security');

        if (!str || str.length === 0) {
            stopwatch && stopwatch.stop();
            return Promise.resolve(str);
        }

        const proto = factory.getPrototypeOfClass(resource);

        if (!factory.isMapped(resource, proto)) {
            stopwatch && stopwatch.stop();
            return Promise.resolve(str);
        }

        const encryptor = factory.getMappedEncryptor(resource, proto);

        if (!(encryptor instanceof Object)) {
            throw new SecurityError(
                'The mapped encryptor for the given resource could not be found. Unable to encrypt');
        }

        const config = this.parseConfig(resource, factory.getMappedConfig(resource, proto) || {});

        str = this.prepareStringForEncryption(str, config);

        return encryptor.encrypt(str, config).then(encrypted => {

            if (config.encode_as_base64) {
                // base64 encode the encrypted string, when configured as such
                encrypted = (Buffer.from(encrypted)).toString('base64');
            }

            stopwatch && stopwatch.stop();

            return Promise.resolve(encrypted);

        });
    }
}

module.exports = EncryptionService;
