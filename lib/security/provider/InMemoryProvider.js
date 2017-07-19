/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractProvider = require('./AbstractProvider');
const InMemoryUser = require('./../user/InMemoryUser');

/**
 * The in-memory provider allows you to specify authentication directly
 * in your configuration file
 */
class InMemoryProvider extends AbstractProvider {
    /**
     * @param {Object} container The service container
     * @param {Object} config The provider config object
     */
    constructor(container, config) {
        super(config);
        this.container = container;
    }

    /**
     * {@inheritdoc}
     */
    supportsResource(resource) {
        return resource instanceof InMemoryUser;
    }

    /**
     * {@inheritdoc}
     */
    getResource(credentials) {

        const { username, password } = credentials;

        const userConfig = this.config.memory.users[username];

        // the username is not found in-memory
        if (userConfig === undefined) {
            return Promise.resolve(null);
        }

        // get a security user
        const user = new InMemoryUser(username, userConfig.password, userConfig.roles || []);

        // if authentication is successful, resolve with the user, otherwise, null

        if (this.config.memory.nonce_encoded) {
            // if nonce encoding is used, we need to reconstruct the encoded string and compare that
            // we cannot use the encryption service to compare
            return Promise.resolve(
                InMemoryProvider.verifyNonce(password, userConfig.password) ? user : null
            );
        }

        // use the encryption service to compare the security user encrypted password with the plaintext credentials
        return this.container.get('security.encryption')
            .compare(user, password, userConfig.password)
            .then(bool => Promise.resolve(bool ? user : null));
    }

    /**
     * {@inheritdoc}
     */
    refreshResource(resource) {
        if (!this.supportsResource(resource)) {
            return Promise.resolve(null);
        }

        // read the resource from the config again, as the roles may have changed
        const userConfig = this.config.memory.users[resource.username];

        // the username is not found in-memory
        if (userConfig === undefined) {
            return Promise.resolve(null);
        }

        // if configured as such, make sure the password hasn't changed
        const changePasswordLogout = this.config.memory.change_password_logout;
        if (changePasswordLogout === undefined || changePasswordLogout) {
            // if the passwords don't match, that means the pw was changed and access is denied
            const a = Buffer.from(userConfig.password);
            const b = Buffer.from(resource.password);
            if (!crypto.timingSafeEqual(a, b)) {
                return Promise.resolve(null);
            }
        }

        // resolve with a new security user
        const user = new InMemoryUser(resource.username, userConfig.password, userConfig.roles || []);
        return Promise.resolve(user);
    }
}

module.exports = InMemoryProvider;
