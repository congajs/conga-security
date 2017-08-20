const process = require('process');

const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const request = require('request');

const rootPath = path.join(__dirname, '..', '..', '..');
const modulePath = path.join(rootPath, 'node_modules');
const appPath = path.join(rootPath, 'spec', 'data', 'projects', 'sample');

process.on('unhandledRejection', (reason, p) => {
    console.error(p, reason);
});

describe('@conga/framework-security; firewall; authenticator;', () => {

    let kernel;

    beforeAll(done => {

        kernel = new Kernel(
            appPath,
            'app',
            'auth_http_form',
            {}
        );

        kernel.addBundlePaths({
            'demo-bundle': path.join(appPath, 'src', 'demo-bundle'),
            '@conga/framework-security': rootPath,
            '@conga/framework-session': path.join(modulePath, '@conga', 'framework-session')
        });

        kernel.boot(() => {
            // need to wait a bit to make sure nedb connections are created
            setTimeout(done, 500);
        });
    });

    describe('http form authentication;', () => {

        describe('single functionality test;', () => {

            return;

            it('should redirect to denied without credentials', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/access-granted',
                    method: 'GET',
                    followAllRedirects: true

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got denied');
                    done();
                });
            });

            it('should load the login route without credentials', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/login',
                    method: 'GET',
                    followAllRedirects: true

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got login');
                    done();
                });
            });

            it('should redirect to failed without credentials', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/_login',
                    method: 'GET',
                    followAllRedirects: true

                }, (error, response, body) => {

                    expect(response.statusCode).toEqual(404);

                    request.post({

                        uri: 'http://localhost:5555/auth/http-form/_login',
                        followAllRedirects: true

                    }, (error, response, body) => {

                        const json = JSON.parse(body);
                        expect(response.statusCode).toEqual(200);
                        expect(json.message).toEqual('got login');
                        expect(json.failed).toBeTruthy();
                        done();
                    });
                });
            });

            it('should redirect to failed with invalid credentials', done => {
                request.post({

                    uri: 'http://localhost:5555/auth/http-form/_login',
                    followAllRedirects: true,
                    form: {
                        username: 'access',
                        password: 'denied'
                    }

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got login');
                    expect(json.failed).toBeTruthy();
                    done();
                });
            });

            it('should create a session on the action route with valid credentials', done => {
                request.post({

                    uri: 'http://localhost:5555/auth/http-form/_login',
                    followAllRedirects: true,
                    jar: true,
                    form: {
                        username: 'http_form',
                        password: 'http_form'
                    }

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got access granted');
                    done();
                });
            });
        });

        describe('session login and logout with cookie;', () => {

            let Cookie;

            it('should create a session', done => {
                request.post({

                    uri: 'http://localhost:5555/auth/http-form/_login',
                    followAllRedirects: false,
                    form: {
                        username: 'http_form',
                        password: 'http_form'
                    }

                }, (error, response, body) => {

                    Cookie = response.headers['set-cookie'];
                    expect(Cookie).toBeTruthy();

                    expect(response.statusCode).toEqual(302);

                    done();
                });
            });

            it('should access granted with session-id auth cookie, no credentials', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/access-granted',
                    followAllRedirects: true,
                    headers: {Cookie}

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got access granted');
                    done();
                });
            });

            it('should log out of established session', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/logout',
                    followAllRedirects: true,
                    headers: {Cookie}

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got login');
                    done();
                });
            });

            it('should access denied with logged out session cookie', done => {
                request({

                    uri: 'http://localhost:5555/auth/http-form/access-granted',
                    followAllRedirects: true,
                    headers: {Cookie}

                }, (error, response, body) => {

                    const json = JSON.parse(body);
                    expect(response.statusCode).toEqual(200);
                    expect(json.message).toEqual('got denied');
                    done();
                });
            });
        });

    });
});
