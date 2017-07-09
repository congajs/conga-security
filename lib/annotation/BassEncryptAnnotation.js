/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// framework libs
const Annotation = require('@conga/annotations').Annotation;

/**
 * The @Bass:Encrypt annotation maps document listeners to the associated document
 * so that when an encrypted field is updated (or inserted), it gets encrypted correctly
 * automatically, using the encryptor mapped to the document.
 */
class BassEncryptAnnotation extends Annotation {
    /**
     * {@inheritdoc}
     */
    static get annotation() { return 'Bass:Encrypt'; }

    /**
     * {@inheritdoc}
     */
    static get targets() { return [Annotation.PROPERTY] }
}

module.exports = BassEncryptAnnotation;
