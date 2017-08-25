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
const AuthToken = require('./AuthToken');
const LogicError= require('./../../error/LogicError');

/**
 * The encrypted-authenticated token is an auth token that has its security credentials encrypted
 */
class EncryptedAuthToken extends AuthToken {
    /**
     * {@inheritDoc}
     * @see AuthToken.getModulePath
     */
    static getModulePath() {
        return __filename;
    }

    /**
     * You cannot serialize an encrypted token
     * @param {AuthToken} token
     * @throws LogicError
     */
    static serialize(token) {
        throw new LogicError('You cannot serialize an encrypted token');
    }

    /**
     * You cannot deserialize an encrypted token
     * @throws LogicError
     */
    static deserialize(serialized) {
        throw new LogicError('You cannot deserialize an encrypted token');
    }

    /**
     * The default cipher algorithm
     * @returns {string}
     */
    static get DEFAULT_ALGORITHM() {
        return 'aes-256-ctr';
    }

    /**
     * Encrypt an AuthToken into an encrypted string
     * @param {AuthToken} token The auth token to encrypt
     * @param {String} [salt] The salt to use when encrypting
     * @param {String} [algorithm] The encryption cipher algorithm to use
     * @returns {String}
     */
    static encrypt(token, salt = '', algorithm = EncryptedAuthToken.DEFAULT_ALGORITHM) {
        if (!(token instanceof AuthToken)) {
            throw new TypeError('Expecting token to be an instance of AuthToken');
        }
        if (token instanceof EncryptedAuthToken) {
            return token.encrypted;
        }
        // the cipher key is stored on the encrypted token - base64(encrypt(json)_key)
        const json = token.constructor.serialize(token);
        const key = crypto.randomBytes(128).toString('hex');
        const cipher = crypto.createCipher(algorithm, salt + key);
        return (new Buffer(
            cipher.update(json, 'utf8', 'hex') + cipher.final('hex') + '_' + key
        )).toString('base64');
    }

    /**
     * Decrypt an AuthToken that has already been encrypted
     * @param {String} token The encrypted token
     * @param {String} [salt] The salt applied to the key during encryption
     * @param {String} [algorithm] The encryption cipher algorithm to use
     * @returns {AuthToken} The decrypted auth token
     */
    static decrypt(token, salt = '', algorithm = EncryptedAuthToken.DEFAULT_ALGORITHM) {
        // the cipher key is stored on the encrypted token - base64(encrypt(json)_key)
        if (token instanceof Object && token.encrypted) {
            token = token.encrypted;
        }
        const parts = Buffer.from(token, 'base64').toString('ascii').split('_');
        const key = parts.pop();
        const decipher = crypto.createDecipher(algorithm, salt + key);
        const json = decipher.update(parts.join('_'), 'hex', 'utf8') + decipher.final('utf8');
        const obj = JSON.parse(json);
        let _class = AuthToken;
        if (obj.module) {
            let C;
            try {
                C = require(obj.module);
            } catch (e) { }
            if (C instanceof Function && C.deserialize instanceof Function) {
                _class = C;
            }
        }
        return _class.deserialize(obj.token || obj);
    }

    /**
     * Previously authenticated token saved in the session
     * @param {AuthToken} token The auth token that you want to have encrypted
     * @param {String} [salt] Salt to apply when encrypting
     * @param {boolean} [isEncrypted] Whether or not the token's credentials are encrypted already
     * @param {String} [algorithm] The encryption cipher algorithm to use
     */
    constructor(
        token,
        salt = '',
        isEncrypted = false,
        algorithm = EncryptedAuthToken.DEFAULT_ALGORITHM
    ) {
        super('encrypted', null, token.realm, [], false, false);

        let encrypted = token;
        if (token.encrypted) {
            encrypted = token.encrypted;
        } else if (!isEncrypted) {
            encrypted = EncryptedAuthToken.encrypt(token, salt, algorithm);
        }

        this.__defineGetter__('encrypted', () => encrypted);
    }
}

module.exports = EncryptedAuthToken;