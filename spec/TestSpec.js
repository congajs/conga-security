const fs = require('fs');
const path = require('path');
const request = require('request');
const Kernel = require('@conga/framework/lib/kernel/TestKernel');

describe("Kernel", () => {

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

            console.log(body);
            expect(response.statusCode).toEqual(200);

            // expect(body.data.attributes['title']).toEqual('Test Title');
            // expect(body.data.attributes['body']).toEqual('This is a test article');
            // expect(body.data.id).not.toBeUndefined();


            done();
        });

    });



});
