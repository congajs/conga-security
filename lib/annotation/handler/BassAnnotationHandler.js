/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// core libs
const path = require('path');

// local libs
const BassEncryptListener = require('./../listener/BassEncryptListener');
const BassEncryptAnnotation = require('./../BassEncryptAnnotation');

/**
 * The paths to all the annotations we support
 * @type {Array<String>}
 */
const paths = [
    path.join(__dirname, '..', 'BassEncryptAnnotation')
];

/**
 * The BassAnnotationHandler registers and processes custom @Bass: annotations for the conga-security bundle
 */
class BassAnnotationHandler {
    /**
     * @param {EncryptionService} encryptionService The encryption service
     */
    constructor(encryptionService) {
        this.encrypt = encryptionService;
    }

    /**
     * Get all annotation paths
     * @returns {Array<String>}
     */
    getAnnotationPaths() {
        return paths;
    }

    /**
     * Process all the annotations through the reader
     * @param {Object} reader The annotation reader
     * @param {ManagerDefinition} definition The bass manager definition
     * @param {Metadata} metadata The bass document metadata
     */
    handleAnnotations(reader, definition, metadata) {
        for (let annotation of reader.propertyAnnotations) {

            // @Bass:Encrypt
            if (annotation instanceof BassEncryptAnnotation) {
                // register a listener for each field
                const listener = new BassEncryptListener(this.encrypt, annotation.target);
                definition.metadataRegistry.registerEventListener('prePersist', listener, 'onPrePersist', 2);
                definition.metadataRegistry.registerEventListener('preUpdate', listener, 'onPreUpdate', 2);
            }

        }
    }
}

module.exports = BassAnnotationHandler;