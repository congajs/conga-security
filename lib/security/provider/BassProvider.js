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
const AbstractProvider = require('./AbstractProvider');
const AuthResourceProxy = require('./../AuthResourceProxy');
const ConfigurationError = require('./../../error/ConfigurationError');

/**
 * The bass security firewall provider allows you to use a bass manager
 * for authentication
 */
class BassProvider extends AbstractProvider {
    /**
     * Get the bass prototype id for a resource
     * @param {Object} resource The resource (bass document)
     * @returns {String|null}
     */
    static getPrototypeId(resource) {
        if (!(resource instanceof Object)) {
            return null;
        }

        if (resource instanceof AuthResourceProxy) {
            resource = resource.getResource();
        }

        resource = Object.getPrototypeOf(resource);
        if (resource._BASS_PROTOTYPE_ID) {
            return resource._BASS_PROTOTYPE_ID;
        }

        return null;
    }

    /**
     * @param {Object} container The service container
     * @param {Object} config The provider config object
     * @throws ConfigurationError for invalid document
     * @throws ConfigurationError for non-registered documents (if we can't find a manger or metadata)
     */
    constructor(container, config) {
        super(config);

        this.container = container;

        // get and validate the document class
        const documentClass = require(
            this.container.get('namespace.resolver').resolveWithSubpath(config.bass.document, 'lib')
        );

        // make sure we found a document class
        if (!documentClass) {
            throw new ConfigurationError(
                'Invalid document configuration for bass provider, "' + config.bass.document + '".');
        }

        // get a new instance of the document (not happy with this!)
        this.document = new documentClass();

        // validate the document
        if (!this.supportsResource(this.document)) {
            throw new ConfigurationError(
                'Invalid document configuration for bass provider, "' + config.bass.document + '".');
        }

        // resolve the manager the document belongs to
        this.manager = this.container.get('bass')
            .createSession()
            .getManagerForModelPrototypeId(BassProvider.getPrototypeId(this.document));

        if (!this.manager) {
            throw new ConfigurationError('No manager was found for document: ' + config.bass.document);
        }

        // pull out some key data that we need from the document's metadata
        const metadata = this.manager.getMetadataForDocument(this.document);
        if (!metadata) {
            throw new ConfigurationError('Unable to find mapped metadata for document: ' + config.bass.document);
        }

        this.documentName = metadata.name;
        this.documentIdField = metadata.idField;
    }

    /**
     * {@inheritdoc}
     */
    supportsResource(resource) {
        if (!BassProvider.getPrototypeId(resource)) {
            return false;
        }

        if (!(this.config.bass.login in resource)) {
            return false;
        }

        if (!(this.config.bass.secret in resource)) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    getResource(credentials) {
        const { login, secret } = credentials;

        return this.manager.findOneBy(this.documentName, { [this.config.bass.login]: login }).then(resource => {

            if (!resource) {
                // nothing was found
                return Promise.resolve(null);
            }

            // if authentication is successful, resolve with the bass resource, otherwise, null
            const encrypted = resource[this.config.bass.secret];

            const authResource = new AuthResourceProxy(resource);

            if (this.config.bass.nonce_encoded) {
                // if nonce encoding is used, we need to reconstruct the encoded string and compare that
                // we cannot use the encryption service to compare
                return Promise.resolve(
                    BassProvider.verifyNonce(secret, encrypted) ? authResource : null
                );
            }

            // nonce encoding is not used, use the encryption service to compare the plain-text secret
            return this.container.get('security.encryption')
                .compare(resource, secret, encrypted)
                .then(bool => Promise.resolve(bool ? authResource : null));
        });
    }

    /**
     * {@inheritdoc}
     */
    refreshResource(resource) {
        if (!this.supportsResource(resource)) {
            return Promise.resolve(null);
        }

        // refresh the resource by fetching it again by its id-field
        return this.manager.find(this.documentName, resource[this.documentIdField]).then(refreshed => {

            // if configured as such, make sure the password hasn't changed
            const changePasswordLogout = this.config.bass.change_password_logout;
            if (changePasswordLogout === undefined || changePasswordLogout) {
                // if the password has changed, then access is denied
                const a = Buffer.from(resource[this.config.bass.secret]);
                const b = Buffer.from(refreshed[this.config.bass.secret]);
                if (!crypto.timingSafeEqual(a, b)) {
                    return Promise.resolve(null);
                }
            }

            // resolve with the new refreshed resource
            return Promise.resolve(refreshed);

        });
    }
}

module.exports = BassProvider;