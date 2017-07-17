const fs = require('fs');
const path = require('path');
const request = require('request');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

describe("@conga/framework-security", () => {

    let kernel;

    beforeAll((done) => {

        kernel = new Kernel(
            path.join(__dirname, '..', 'spec', 'data', 'projects', 'sample'),
            'app',
            'test',
            {}
        );

        kernel.addBundlePaths({
            //'conga-bass': path.join(__dirname, '..', 'node_modules', 'conga-bass'),
            //'conga-validation': path.join(__dirname, '..', '..', 'conga-validation'), // CHANGE THIS!!!
            //'bass-nedb': path.join(__dirname, '..', 'node_modules', 'bass-nedb'),
            'demo-bundle': path.join(__dirname, '..', 'spec', 'data', 'projects', 'sample', 'src', 'demo-bundle'),
            '@conga/framework-security': path.join(__dirname, '..')
        });


        kernel.boot(() => {

            // need to wait a bit to make sure nedb connections are created
            setTimeout(() => {

                done();

            }, 500);

        });

    });

    it("should load the index route without problems", (done) => {

        request({

            uri: 'http://localhost:5555/',
            method: 'GET'

        }, (error, response, body) => {

            expect(response.statusCode).toEqual(200);
            expect(body).toEqual('{"foo":"bar"}');

            done();
        });

    });

    it("should return an access denied error response for an in-memory firewall with no auth", (done) => {

        request({

            uri: 'http://localhost:5555/admin/secure',
            method: 'GET'

        }, (error, response, body) => {

            const json = JSON.parse(body);
            expect(response.statusCode).toEqual(401);
            expect(json.message).toEqual('Unauthorized');
            done();

        });

    });

    it("should return an access denied error response when logging in via HTTP basic auth (plaintext) to an in-memory firewall with invalid credentials", (done) => {

        request({

            uri: 'http://localhost:5555/admin/secure',
            method: 'GET',
            auth: {
                user: 'access',
                pass: 'denied',
                sendImmediately: true
            }

        }, (error, response, body) => {

            const json = JSON.parse(body);
            expect(response.statusCode).toEqual(403);
            expect(json.message).toEqual('Access Denied');
            done();

        });

    });


    it("should return a success response when logging in via HTTP basic auth (plaintext) to an in-memory firewall", (done) => {

        request({

            uri: 'http://localhost:5555/admin/secure',
            method: 'GET',
            auth: {
                user: 'bar',
                pass: 'bar',
                sendImmediately: true
            }

        }, (error, response, body) => {

            expect(response.statusCode).toEqual(200);
            expect(body).toEqual('{"message":"got in"}');
            done();

        });

    });

});