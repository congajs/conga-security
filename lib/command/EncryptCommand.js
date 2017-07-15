/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// local libs
const InvalidArgumentError = require('./../error/InvalidArgumentError');

/**
 * This command encrypts a string for a given resource
 */
module.exports = {

	/**
	 * Set up configuration for this command
	 * @type {Object}
	 */
	config: {
		command: "security:encrypt",
		description: "Encrypt a string for a resource namespace",
		options: {
			'value' : ['-v, --value [value]', 'Provide a value to encrypt'],
            'path' : ['-p, --path [value]', 'Provide a mapped resource path'],
			'compare' : ['-c, --compare [value]', 'Provide an encrypted value to see if it compares.']
		},
		arguments: []
	},

	/**
	 * Run the command
	 * @return {void}
	 */
	run: (container, args, options, cb) => {
		const { path, value, compare } = options;

		container.get('logger').debug('running security:encrypt');

		const resource = require(container.get('namespace.resolver').resolveWithSubpath(path, 'lib'));
		if (!resource) {
			throw new InvalidArgumentError('Invalid namespace provided, "' + path + '"');
		}

		const encryption = container.get('security.encryption');

		let output = '\n\n\n';
		output += 'Path:\t\t' + path + '\n';
		output += 'Decrypted:\t' + value + '\n';

		if (compare) {

            encryption.compare(resource, value, compare).then(bool => {

            	output += 'Compares:\t' + (bool ? 'YES' : 'NO') + '\n';
                output += 'Encrypted:\t' + compare + '\n';
                container.get('logger').debug(output + '\n\n');
                cb();

            }).catch(err => {

                output += 'Encrypted:\t' + compare + '\n';
            	output += 'Error:\n' + (err.stack || err) + '\n';
                container.get('logger').debug(output + '\n\n');
                cb();

            });

		} else {

            encryption.encrypt(resource, value).then(encrypted => {

            	output += 'Encrypted:\t' + encrypted + '\n';
                container.get('logger').debug(output + '\n\n');
                cb();

            }).catch(err => {

                output += 'Error:\n' + (err.stack || err) + '\n';
                container.get('logger').debug(output + '\n\n');
                cb();

            });

        }
	}
};