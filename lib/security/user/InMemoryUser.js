/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const AuthUser = require('./AuthUser');

/**
 * The in-memory user exists so you can provide a separate encoder for in-memory users
 * vs other authenticated users.
 */
class InMemoryUser extends AuthUser {

    // empty

}

module.exports = InMemoryUser;