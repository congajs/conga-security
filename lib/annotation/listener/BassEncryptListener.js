/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * The BassEncryptListener class is registered with Bass to automatically hash a resource's encrypted field(s)
 * when it is created or updated
 */
class BassEncryptListener {
    /**
     * Construct with conga container
     * @param {EncryptionService} encryptionService
     * @param {String} field The field being encrypted
     * @returns {void}
     */
    constructor(encryptionService, field) {
        this.encryption = encryptionService;
        this.field = field
    }

    /**
     * Hash password when a resource is first created
     * @param {Object} event The event object
     * @param {Function} cb The callback function
     * @returns {void}
     */
    onPrePersist(event, cb) {
        if (!event.document.__isNew) {
            cb();
            return;
        }
        this.encrypt(event.document, function () {
            cb();
        });
    }

    /**
     * Hash password when a resource is updated
     * @param {Object} event The event object
     * @param {Function} cb The callback function
     * @returns {void}
     */
    onPreUpdate(event, cb) {
        const resource = event.document;

        if (resource.__isNew !== false) {
            cb();
            return;
        }

        // check if there is a new password
        // we are comparing the data that was loaded vs. the data that is about to be saved
        if (resource.__loadedData !== undefined &&
            resource.__loadedData[this.field] !== resource[this.field]
        ) {
            this.encrypt(resource, cb);
        } else {
            cb();
        }
    }

    /**
     * Encrypt a user's password
     * @param {Object} resource Any document resource
     * @param {Function} cb The callback function
     * @returns {void}
     */
    encrypt(resource, cb) {
        const value = resource[this.field];
        if (typeof value !== 'string') {
            cb();
            return;
        }
        this.encryption.encrypt(resource, value).then(encrypted => {
            resource[this.field] = encrypted;
            cb();
        }).catch(err => { throw err });
    }
}

module.exports = BassEncryptListener;
