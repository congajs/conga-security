const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const request = require('request');

const rootPath = path.join(__dirname, '..', '..');
const modulePath = path.join(rootPath, 'node_modules');
const appPath = path.join(rootPath, 'spec', 'data', 'projects', 'sample');

describe('@conga/framework-security; firewall; session realms;', () => {

    let kernel;

    beforeAll((done) => {

        kernel = new Kernel(
            appPath,
            'app',
            'session_realms',
            {}
        );

        kernel.addBundlePaths({
            'demo-bundle': path.join(appPath, 'src', 'demo-bundle'),
            '@conga/framework-security': rootPath,
            '@conga/framework-session': path.join(modulePath, '@conga', 'framework-session')
        });


        kernel.boot(() => {

            // need to wait a bit to make sure nedb connections are created
            setTimeout(() => {

                done();

            }, 500);

        });

    });

    describe('data isolation;', () => {

        let Cookie;

        const cookieCheck = response => {
            if (response.headers instanceof Object && 'set-cookie' in response.headers) {
                Cookie = response.headers['set-cookie'];
            }
        };

        const getHeaders = () => {
            if (Cookie) {
                return { Cookie };
            }
            return {};
        };

        it("should set and return data in security realm one", (done) => {

            request({

                uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                method: 'GET',
                auth: {
                    user: 'foo',
                    pass: 'foo',
                    sendImmediately: true
                },
                headers: getHeaders()

            }, (error, response, body) => {

                cookieCheck(response);

                const json = JSON.parse(body);

                expect(response.statusCode).toEqual(200);

                expect(json).toEqual(jasmine.objectContaining({
                    realm: 'session_realm_one',
                    requestRealm: 'session_realm_one',
                    sessionValue: 'The session realm is session_realm_one',
                    globalValue: 'Hi! I am a global variable!'
                }));

                expect(json.keys).toEqual(jasmine.arrayContaining([
                    'session_realm', 'session_global']));

                expect(json.data).toEqual(jasmine.objectContaining({
                    session_realm: 'The session realm is session_realm_one',
                    session_global: 'Hi! I am a global variable!'
                }));

                done();

            });

        });

        it("should set and return data in security realm two", done => {

            request({

                uri: 'http://localhost:5555/session/realm/session_realm_two/set',
                method: 'GET',
                auth: {
                    user: 'foo',
                    pass: 'foo',
                    sendImmediately: true
                },
                headers: getHeaders()

            }, (error, response, body) => {

                cookieCheck(response);

                const json = JSON.parse(body);

                expect(response.statusCode).toEqual(200);

                expect(json).toEqual(jasmine.objectContaining({
                    realm: 'session_realm_two',
                    requestRealm: 'session_realm_two',
                    sessionValue: 'The session realm is session_realm_two',
                    globalValue: 'Hi! I am a global variable!'
                }));

                expect(json.keys).toEqual(jasmine.arrayContaining([
                    'session_realm', 'session_global']));

                expect(json.data).toEqual(jasmine.objectContaining({
                    session_realm: 'The session realm is session_realm_two',
                    session_global: 'Hi! I am a global variable!'
                }));

                done();

            });

        });

        it("should only get data from security realm one", done => {

            request({

                uri: 'http://localhost:5555/session/realm/session_realm_one/get',
                method: 'GET',
                auth: {
                    user: 'foo',
                    pass: 'foo',
                    sendImmediately: true
                },
                headers: getHeaders()
            }, (error, response, body) => {

                cookieCheck(response);

                const json = JSON.parse(body);

                expect(response.statusCode).toEqual(200);

                expect(json).toEqual(jasmine.objectContaining({
                    realm: 'session_realm_one',
                    requestRealm: 'session_realm_one',
                    sessionValue: 'The session realm is session_realm_one',
                    globalValue: 'Hi! I am a global variable!'
                }));

                expect(json.keys).toEqual(jasmine.arrayContaining([
                    'session_realm', 'session_global']));

                expect(json.data).toEqual(jasmine.objectContaining({
                    session_realm: 'The session realm is session_realm_one',
                    session_global: 'Hi! I am a global variable!'
                }));

                done();

            });

        });

        it('should only get data from security realm two', done => {

            request({

                uri: 'http://localhost:5555/session/realm/session_realm_two/get',
                method: 'GET',
                auth: {
                    user: 'foo',
                    pass: 'foo',
                    sendImmediately: true
                },
                headers: getHeaders()
            }, (error, response, body) => {

                cookieCheck(response);

                const json = JSON.parse(body);

                expect(response.statusCode).toEqual(200);

                expect(json).toEqual(jasmine.objectContaining({
                    realm: 'session_realm_two',
                    requestRealm: 'session_realm_two',
                    sessionValue: 'The session realm is session_realm_two',
                    globalValue: 'Hi! I am a global variable!'
                }));

                expect(json.keys).toEqual(jasmine.arrayContaining([
                    'session_realm', 'session_global']));

                expect(json.data).toEqual(jasmine.objectContaining({
                    session_realm: 'The session realm is session_realm_two',
                    session_global: 'Hi! I am a global variable!'
                }));

                done();

            });

        });

        it('should not share data between sessions', done => {

            request({

                uri: 'http://localhost:5555/session/realm/session_realm_two/get',
                method: 'GET',
                auth: {
                    user: 'foo',
                    pass: 'foo',
                    sendImmediately: true
                }
                // no headers!

            }, (error, response, body) => {

                // no cookie check!

                const json = JSON.parse(body);

                expect(response.statusCode).toEqual(200);

                expect(json).toEqual(jasmine.objectContaining({
                    realm: 'session_realm_two',
                    requestRealm: 'session_realm_two'
                }));

                expect(json).not.toEqual(jasmine.objectContaining({
                    sessionValue: 'The session realm is session_realm_two',
                    globalValue: 'Hi! I am a global variable!'
                }));

                expect(json.keys).not.toEqual(jasmine.arrayContaining([
                    'session_realm', 'session_global']));

                expect(json.data).not.toEqual(jasmine.objectContaining({
                    session_realm: 'The session realm is session_realm_two',
                    session_global: 'Hi! I am a global variable!'
                }));

                done();

            });

        });


    });

});
