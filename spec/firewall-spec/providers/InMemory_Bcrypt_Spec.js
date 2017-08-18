const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const userTest = require('../../../spec/UserTests.js');
const adminTest = require('../../../spec/AdminTests.js');
const annotationTest = require('../../../spec/AnnotationTests');
const anonymousTest = require('../../../spec/AnonymousTests');

describe("@conga/framework-security; firewall; provider; in-memory; bcrypt;", () => {

    let kernel;

    beforeAll((done) => {

        kernel = new Kernel(
            path.join(__dirname, '..', '..', '..', 'spec', 'data', 'projects', 'sample'),
            'app',
            'in_memory_bcrypt',
            {}
        );

        kernel.addBundlePaths({
            //'conga-bass': path.join(__dirname, '..', 'node_modules', 'conga-bass'),
            //'conga-validation': path.join(__dirname, '..', '..', 'conga-validation'), // CHANGE THIS!!!
            //'bass-nedb': path.join(__dirname, '..', 'node_modules', 'bass-nedb'),
            'demo-bundle': path.join(__dirname, '..', '..', '..', 'spec', 'data', 'projects', 'sample', 'src', 'demo-bundle'),
            '@conga/framework-security': path.join(__dirname, '..', '..', '..')
        });


        kernel.boot(() => {

            // need to wait a bit to make sure nedb connections are created
            setTimeout(() => {

                done();

            }, 500);

        });

    });

    describe("anonymous;", anonymousTest);

    describe("user;", userTest);

    describe("admin;", adminTest);

    describe("annotations;", annotationTest);

});
