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
 * Plain Text Encryptor
 */
class PlainTextEncryptor extends AbstractEncryptor {
    /**
     * {@inheritDoc}
     * @see AbstractEncryptor.encrypt
     */
    encrypt(str, config = 'not-used') {
        return Promise.resolve((Buffer.from(str)).toString('ascii'));
    }
}

module.exports = PlainTextEncryptor;