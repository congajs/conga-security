const request = require('request');

module.exports = () => {

    it("should load the index route", (done) => {
        request({

            uri: 'http://localhost:5555/',
            method: 'GET'

        }, (error, response, body) => {

            expect(response.statusCode).toEqual(200);
            expect(body).toEqual('{"foo":"bar"}');

            done();
        });
    });
};