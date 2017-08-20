const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const request = require('request');

const rootPath = path.join(__dirname, '..', '..');
const modulePath = path.join(rootPath, 'node_modules');
const appPath = path.join(rootPath, 'spec', 'data', 'projects', 'sample');

describe('@conga/framework-security; firewall; session realms;', () => {

    let kernel, Cookie;

    const cookieCheck = response => {
        if (response.headers instanceof Object && 'set-cookie' in response.headers) {
            Cookie = response.headers['set-cookie'];
        }
    };

    const getHeaders = () => {
        if (Cookie) {
            return {Cookie};
        }
        return {};
    };

    const clearCookie = () => { Cookie = null; };

    const checkRealmResponse = (realm, response, body) => {
        const json = JSON.parse(body);

        expect(response.statusCode).toEqual(200);

        expect(json).toEqual(jasmine.objectContaining({
            realm: realm,
            requestRealm: realm,
            sessionValue: 'The session realm is ' + realm,
            globalValue: 'Hi! I am a global variable!'
        }));

        expect(json.keys).toEqual(jasmine.arrayContaining(
            ['session_realm', 'session_global']));

        expect(json.data).toEqual(jasmine.objectContaining({
            session_realm: 'The session realm is ' + realm,
            session_global: 'Hi! I am a global variable!'
        }));
    };

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

    describe('session;', () => {


        describe('shared;', () => {

            describe('data isolation;', () => {

                beforeAll(done => {
                    clearCookie();
                    done();
                });

                it("should set and return data in security realm one", (done) => {
                    request({

                        uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                        method: 'GET',
                        auth: {
                            user: 'foo',
                            pass: 'foo',
                            sendImmediately: true
                        }
                        // no headers!  this is the first auth

                    }, (error, response, body) => {

                        cookieCheck(response);

                        checkRealmResponse('session_realm_one', response, body);
                        done();
                    });
                });

                it("should set and return data in security realm two", done => {
                    request({

                        uri: 'http://localhost:5555/session/realm/session_realm_two/set',
                        method: 'GET',

                        // session data is saved together with previous cookie's session-id
                        headers: getHeaders()

                    }, (error, response, body) => {

                        cookieCheck(response);

                        checkRealmResponse('session_realm_two', response, body);
                        done();
                    });
                });

                it("should only get data from security realm one", done => {
                    request({

                        uri: 'http://localhost:5555/session/realm/session_realm_one/get',
                        method: 'GET',

                        // session data is saved together with previous cookie's session-id
                        headers: getHeaders()

                    }, (error, response, body) => {

                        cookieCheck(response);

                        checkRealmResponse('session_realm_one', response, body);
                        done();
                    });
                });

                it('should only get data from security realm two', done => {
                    request({

                        uri: 'http://localhost:5555/session/realm/session_realm_two/get',
                        method: 'GET',

                        // session data is saved together with previous cookie's session-id
                        headers: getHeaders()

                    }, (error, response, body) => {

                        cookieCheck(response);

                        checkRealmResponse('session_realm_two', response, body);
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

                        expect(json.keys).not.toEqual(jasmine.arrayContaining(
                            ['session_realm', 'session_global']));

                        expect(json.data).not.toEqual(jasmine.objectContaining({
                            session_realm: 'The session realm is session_realm_two',
                            session_global: 'Hi! I am a global variable!'
                        }));

                        done();
                    });
                });
            });
        });


        describe('not shared;', () => {

            beforeAll(done => {
                clearCookie();
                done();
            });

            it('should set and return data for realm three', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_three/set',
                    method: 'GET',
                    auth: {
                        user: 'foo',
                        pass: 'foo',
                        sendImmediately: true
                    }

                }, (error, response, body) => {

                    cookieCheck(response);
                    expect(Cookie).toBeTruthy();

                    checkRealmResponse('session_realm_three', response, body);
                    done();
                });
            });

            it('should return data for realm three using cookie', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_three/set',
                    method: 'GET',
                    headers: getHeaders()

                }, (error, response, body) => {

                    checkRealmResponse('session_realm_three', response, body);
                    done();
                });
            });

            it('should not allow access to realm four with cookie from realm three', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_four/get',
                    method: 'GET',
                    headers: getHeaders()

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(401);
                    expect(json).toEqual(jasmine.objectContaining({message: 'Unauthorized'}));
                    done();
                });
            });

            it('should set and return data for realm four', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_four/set',
                    method: 'GET',
                    auth: {
                        user: 'foo',
                        pass: 'foo',
                        sendImmediately: true
                    }

                }, (error, response, body) => {

                    clearCookie();

                    cookieCheck(response);
                    expect(Cookie).toBeTruthy();

                    checkRealmResponse('session_realm_four', response, body);
                    done();
                });
            });

            it('should return data for realm four using cookie', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_four/set',
                    method: 'GET',
                    headers: getHeaders()

                }, (error, response, body) => {

                    checkRealmResponse('session_realm_four', response, body);
                    done();
                });
            });

            it('should not allow access to realm three with cookie from realm four', done => {
                request({

                    uri: 'http://localhost:5555/session/realm/session_realm_three/get',
                    method: 'GET',
                    headers: getHeaders()

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(401);
                    expect(json).toEqual(jasmine.objectContaining({message: 'Unauthorized'}));
                    done();
                });
            });
        });


    });

});
