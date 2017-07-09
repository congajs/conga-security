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

/**
 * The default configuration (used for overrides)
 * @type {Object}
 */
const DEFAULT_CONFIG = {
    salt: null,
    saltRounds: 10
};

/**
 * Bcrypt Encryptor
 */
class BcryptEncryptor extends AbstractEncryptor {
    /**
     * @param {bcrypt} bcrypt The bcrypt service
     */
    constructor(bcrypt) {
        super();
        this.bcrypt = bcrypt;
    }

    /**
     * {@inheritDoc}
     */
    compare(str, encrypted, config = null) {
        return new Promise((resolve, reject) => {
            this.bcrypt.compare(str, encrypted, (err, bool) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(bool);
                }
            });
        });
    }

    /**
     * {@inheritDoc}
     */
    encrypt(str, config = DEFAULT_CONFIG) {
        config = Object.assign({}, config, DEFAULT_CONFIG);
        return new Promise((resolve, reject) => {
            let salt = config.salt;
            if (config.fields instanceof Object && config.fields.salt) {
                salt = config.fields.salt;
            }
            this.bcrypt.hash(str, salt || config.saltRounds, (err, hash) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(hash);
                }
            });
        });
    }
}

module.exports = BcryptEncryptor;