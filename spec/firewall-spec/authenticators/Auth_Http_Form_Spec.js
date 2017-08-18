const path = require('path');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

const request = require('request');

const rootPath = path.join(__dirname, '..', '..', '..');
const modulePath = path.join(rootPath, 'node_modules');
const appPath = path.join(rootPath, 'spec', 'data', 'projects', 'sample');

describe('@conga/framework-security; firewall; authenticator;', () => {

    let kernel;

    beforeAll((done) => {

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
            setTimeout(() => {

                done();

            }, 500);

        });

    });

    describe('http form authentication;', () => {

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

        it('should redirect to denied on the action route without credentials', done => {

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
                    expect(json.message).toEqual('got denied');

                    done();
                });

            });

        });

        it('should redirect to denied on the action route with invalid credentials', done => {

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
                expect(json.message).toEqual('got denied');

                done();
            });

        });

        it('should create a session on the action route with valid credentials', done => {

            request.post({

                uri: 'http://localhost:5555/auth/http-form/_login',
                jar: true,
                followAllRedirects: true,
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

});
