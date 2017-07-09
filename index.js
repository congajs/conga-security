/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

module.exports = {

    AuthResource: require('./lib/security/AuthResource'),

    Authenticator: {
        AbstractAuthenticator: require('./lib/security/authenticator/AbstractAuthenticator')
    },

    Encryption: {
        AbstractEncryptor: require('./lib/security/encryption/AbstractEncryptor')
    },

    Error: {
        AccessDeniedError: require('./lib/error/AccessDeniedError'),
        ConfigurationError: require('./lib/error/ConfigurationError'),
        HttpError: require('./lib/error/HttpError'),
        InvalidArgumentError: require('./lib/error/InvalidArgumentError'),
        LogicError: require('./lib/error/LogicError'),
        SecurityError: require('./lib/error/SecurityError')
    },

    Provider: {
        AbstractProvider: require('./lib/security/provider/AbstractProvider'),
        AbstractProviderConfig: require('./lib/security/provider/AbstractProviderConfig')
    },

    Token: {
        AuthToken: require('./lib/security/token/AuthToken'),
        AuthTokenCredentials: require('./lib/security/token/AuthTokenCredentials'),
        PreAuthToken: require('./lib/security/token/PreAuthToken')
    },

    User: {
        AuthUser: require('./lib/security/user/AuthUser')
    }

};