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

    const checkRealmResponse = (realm, response, body, username = 'foo') => {
        const json = JSON.parse(body);

        expect(response.statusCode).toEqual(200);

        expect(json).toEqual(jasmine.objectContaining({
            realm: realm,
            requestRealm: realm,
            username: username,
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


    describe('shared;', () => {

        describe('access;', () => {

            beforeAll(done => {
                clearCookie();
                done();
            });

            it('should set a session for security realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                    method: 'GET',
                    auth: {
                        user: 'foo',
                        pass: 'foo',
                        sendImmediately: true
                    }
                }, (error, response, body) => {

                    expect(response.headers['set-cookie']).toBeTruthy();

                    cookieCheck(response);
                    expect(Cookie).toBeTruthy();

                    done();
                });
            });

            it('should access realm two with cookie from realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_two/set',
                    method: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_two', response, body);
                    done();

                });
            });

            it('should access denied on realm three with cookie from realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_three/get',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should access denied on realm four with cookie from realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_four/get',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should create a session in realm five with auth', done => {
                clearCookie();
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_five/set',
                    methods: 'GET',
                    auth: {
                        user: 'bar',
                        pass: 'bar',
                        sendImmediately: true
                    }
                }, (error, response, body) => {

                    cookieCheck(response);
                    checkRealmResponse('session_realm_five', response, body, 'bar');
                    done();

                });
            });

            it('should use cookie from realm five to access realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_one', response, body, 'bar');
                    done();

                });
            });

            it('should not be able to log out of realm one using cookie from realm five', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/logout',
                    methods: 'GET',
                    headers: getHeaders(),
                    followAllRedirects: true
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_one', response, body, 'bar');
                    done();

                });
            });

            it('should log out of realm five with cookie', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_five/logout',
                    methods: 'GET',
                    headers: getHeaders(),
                    followAllRedirects: true
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should be logged out of realm one with cookie', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/get',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should create a session in realm one with auth', done => {
                clearCookie();
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                    methods: 'GET',
                    auth: {
                        user: 'foo',
                        pass: 'foo',
                        sendImmediately: true
                    }
                }, (error, response, body) => {

                    cookieCheck(response);

                    checkRealmResponse('session_realm_one', response, body);
                    done();

                });
            });

            it('should access denied to realm five with cookie from realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_five/get',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should login to realm five with auth, using cookie from realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_five/set',
                    methods: 'GET',
                    headers: getHeaders(),
                    auth: {
                        user: 'bar',
                        pass: 'bar',
                        sendImmediately: true
                    }
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_five', response, body, 'bar');
                    done();

                });
            });

            it('should be logged into realm one', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_one', response, body, 'foo');
                    done();

                });
            });

            it('should not be able to log out of realm one using cookie', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/logout',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    checkRealmResponse('session_realm_one', response, body, 'bar');
                    done();

                });
            });

            it('should log out of realm five using cookie', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_five/logout',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });

            it('should be logged out of realm one using cookie', done => {
                request({
                    uri: 'http://localhost:5555/session/realm/session_realm_one/set',
                    methods: 'GET',
                    headers: getHeaders()
                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(401);
                    done();

                });
            });
        });

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
