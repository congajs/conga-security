/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const LogicError = require('./../error/LogicError');
const ConfigurationError = require('./../error/ConfigurationError');

/**
 * Register encryption algorithmes from the security configuration
 * @param {Object} container The service container
 * @returns {void}
 */
const registerAlgorithms = (container) => {

    // find all the tagged security encryptors
    const encryptors = container.getTagsByName('security.encryptor');

    // if we have no encryptors, move on
    if (!encryptors || encryptors.length === 0) {
        return;
    }

    // sort the tags by priority
    container.get('conga.ioc.tag.sorter').sortByPriority(encryptors);

    // add each tagged encryptor to the encryptor factory
    const encryptionService = container.get('security.encryption');

    for (let encryptor of encryptors) {
        encryptionService.registerAlgorithm(encryptor.getParameter('algorithm'), container.get(encryptor.getServiceId()));
    }

};

/**
 * Map encrypted resources from the security configuration
 * @param {Object} container The service container
 * @returns {void}
 */
const mapResources = (container) => {
    // find all the configured security encryption resources
    const security = container.get('config').get('security');

    if (!(security.encryption instanceof Object)) {
        return;
    }

    const namespaceResolver = container.get('namespace.resolver');
    const encryptionService = container.get('security.encryption');

    for (let key in security.encryption) {

        // get the encryptor configuration object
        let config = security.encryption[key];
        if (!(config instanceof Object) || config.path === undefined) {
            throw new ConfigurationError('Invalid security encryption configuration for security.encryption.' + key);
        }

        // get the mapped resource by namespace
        let resource = require(namespaceResolver.resolveWithSubpath(config.path, 'lib'));
        if (!resource) {
            throw new ConfigurationError('Invalid path provided for security.encryption.' + key);
        }

        // get the mapped encryptor
        let encryptor = encryptionService.getEncryptorForConfig(config);
        if (!encryptor) {
            throw new ConfigurationError('Invalid security encryption configured for security.encryption.' + key);
        }

        // map the resource to the encryptor
        encryptionService.mapResource(resource, encryptor, config);
    }
};

/**
 * The encryption listener is used to map encryptors to resources at runtime
 */
class EncryptionListener {
    /**
     * Map encryptors to resources when the kernel compiles
     * @param {Object} event The event object
     * @param {Function} next The function to invoke the next event listener in the series
     * @returns {void}
     */
    onKernelCompile(event, next) {

        const { container } = event;

        registerAlgorithms(container);

        mapResources(container);

        next();

    }
}

module.exports = EncryptionListener;