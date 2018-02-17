/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AbstractAuthenticator = require('./AbstractAuthenticator');
const PreAuthToken = require('./../token/PreAuthToken');
const AuthTokenCredentials = require('./../token/AuthTokenCredentials');

/**
 * The HTTP basic authenticator is used to authenticate HTTP Basic Auth requests
 */
class HttpBasicAuthenticator extends AbstractAuthenticator {
    /**
     * Parse the authorization header
     * @param {Object} request The request object
     * @param {Boolean} [addResponseHeader] True to send back a 401 when no header is found
     * @param {String} [realm] The security realm being authenticated; used in the response header
     * @returns {Promise}
     */
    parseHeader(request, addResponseHeader = false, realm = null) {
        const scheme = this.options.scheme || 'Basic';

        // if there is no authorization header, respond in kind
        if (!request.headers.authorization) {
            let err = this.getAccessDeniedError('Unauthorized', 401);
            if (addResponseHeader) {
                err.addResponseHeader('WWW-Authenticate', scheme + ' realm="' + realm + '"');
            }
            return Promise.reject(err);
        }

        // TODO: add the scheme to the regex

        // get the auth info from the http auth header (ex: 'Authorizaion: Basic Zm9vOmJhcg==')
        const header = request.headers.authorization.replace(/^.+\s+([^\s]+)$/g, '$1');
        const auth = (new Buffer(header, 'base64')).toString('ascii');
        const [ username, password ] = auth.split(':');

        return Promise.resolve({username, password});
    }

    /**
     * {@inheritDoc}
     */
    createToken(request, realm = 'http-basic') {
        const { response_header } = this.options;
        const addResponseHeader = response_header === undefined || response_header;
        return this.parseHeader(request, addResponseHeader, realm).then(authorization => {
            const { username, password } = authorization;
            return new PreAuthToken(new AuthTokenCredentials(username, password), realm);
        });
    }
}

module.exports = HttpBasicAuthenticator;
