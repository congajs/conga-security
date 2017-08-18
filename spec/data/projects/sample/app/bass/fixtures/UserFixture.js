// core libs
const path = require('path');

// framework libs
const { AbstractFixture } = require('@conga/framework-bass');

/**
 * This fixture loads dummy users and administrators
 */
module.exports = class UserFixture extends AbstractFixture {

    /**
     * Get the priority order to run this fixture on
     * @returns {Number}
     */
    getOrder() {
        return 1;
    }

    /**
     * Ge tthe name of the model that this fixture is for
     * @returns {String}
     */
    getModelName() {
        return 'User';
    }

    /**
     * Load the data into the database
     * @param {function} next The callback function
     * @returns {void}
     */
    load(next) {

        const manager = this.getManager();

        this.mapFromFile(path.join(__dirname, 'data', 'UserFixture.csv'), (model, row, idx, cb) => {

            model.referenceId = row.id;
            model.username = row.username;
            model.password = row.password;
            model.firstName = row.first_name;
            model.lastName = row.last_name;
            model.roles = Function('return ' + row.roles)();

            // add a reference to this user so other fixtures can reference it
            this.addReference('user-' + row.id, model);

            manager.persist(model);

        }, () => {

            manager.flush().then(next).catch(err => {
                console.error(err.stack || err);
            });

        });
    }

}