/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// framework libs
const { AbstractCommand } = require('@conga/framework').command;

// local libs
const InvalidArgumentError = require('./../error/InvalidArgumentError');

/**
 * This command encrypts a string for a given resource
 */
module.exports = class EncryptCommand extends AbstractCommand {
    /**
     * The command
     *
     * @return {String}
     */
    static get command() {
        return 'security:encrypt';
    }

    /**
     * The command description
     *
     * @return {String}
     */
    static get description() {
        return 'Encrypt a string for a resource namespace';
    }

    /**
     * Hash of command options
     *
     * @return {Object}
     */
    static get options() {
        return {
            'value' : ['-v, --value [value]', 'Provide a value to encrypt'],
            'path' : ['-p, --path [value]', 'Provide a mapped resource path'],
            'compare' : ['-c, --compare [value]', 'Provide an encrypted value to see if it compares.']
        };
    }

    /**
     * Array of command argument names
     *
     * @return {Array<String>}
     */
    static get arguments() {
        return [];
    }

    /**
     * Execute the command
     *
     * @param  {CommandInput}  input   the command input data
     * @param  {CommandOutput} output  the output writer
     * @param  {Function}      next    the next callback
     * @return {void}
     */
    execute(input, output, next) {

    	this.output = output;

        const path = input.getOption('path');
        const value = input.getOption('value');
        const compare = input.getOption('compare');

        output.writeln('running security:encrypt');

        const resource = require(this.container.get('namespace.resolver')
			.resolveWithSubpath(path, 'lib'));

        if (!resource) {
            throw new InvalidArgumentError('Invalid namespace provided, "' + path + '"');
        }

        const encryption = this.container.get('security.encryption');

        let display = '\n\n\n';
        display += 'Path:\t\t' + path + '\n';
        display += 'Decrypted:\t' + value + '\n';

        if (compare) {

            encryption.compare(resource, value, compare).then(bool => {

                display += 'Compares:\t' + (bool ? 'YES' : 'NO') + '\n';
                display += 'Encrypted:\t' + compare + '\n';
                output.writeln(display + '\n\n');
                next();

            }).catch(err => {

                output += 'Encrypted:\t' + compare + '\n';
                output += 'Error:\n' + (err.stack || err) + '\n';
                output.writeln(display + '\n\n');
                next();

            });

        } else {

            encryption.encrypt(resource, value).then(encrypted => {

                display += 'Encrypted:\t' + encrypted + '\n';
                output.writeln(display + '\n\n');
                next();

            }).catch(err => {

                display += 'Error:\n' + (err.stack || err) + '\n';
                output.writeln(display + '\n\n');
                next();

            });

        }

    }

};