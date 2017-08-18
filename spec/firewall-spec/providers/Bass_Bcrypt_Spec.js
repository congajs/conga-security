const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const rootPath = path.join(__dirname, '..', '..', '..');
const modulePath = path.join(rootPath, 'node_modules');
const appPath = path.join(rootPath, 'spec', 'data', 'projects', 'sample');

const Module = require('module');
const originalLoad = Module._load;

Module._load = function (request, parent) {

    let idx = request.indexOf('bass-nedb');
    if (idx !== -1) {
        request = path.join(modulePath, request.substr(idx));
    }

    return originalLoad.call(this, request, parent);
};

const userTest = require('../../../spec/UserTests.js');
const adminTest = require('../../../spec/AdminTests.js');
const annotationTest = require('../../../spec/AnnotationTests');
const anonymousTest = require('../../../spec/AnonymousTests');

describe("@conga/framework-security; firewall; provider; bass; bcrypt;", () => {

    let kernel;

    beforeAll((done) => {

        kernel = new Kernel(
            appPath,
            'app',
            'bass_bcrypt',
            {}
        );

        kernel.addBundlePaths({
            'demo-bundle': path.join(appPath, 'src', 'demo-bundle'),
            '@conga/framework-security': rootPath,
            '@conga/framework-bass': path.join(modulePath, '@conga', 'framework-bass')
        });


        kernel.boot(() => {
            // need to wait a bit to make sure nedb connections are created
            setTimeout(() => {

                kernel.container.get('bass.fixture.runner').runFixtures(
                    path.join(appPath, 'app', 'bass', 'fixtures'),
                    null,
                    () => {
                        done();
                    }
                )

            }, 500);
        });

    });

    describe("anonymous;", anonymousTest);

    describe("user;", userTest);

    describe("admin;", adminTest);

    describe("annotations;", annotationTest);

});
