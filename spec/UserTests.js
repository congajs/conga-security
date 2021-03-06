const request = require('request');

module.exports = () => {

    it("should access denied without auth credentials", (done) => {
        request({

            uri: 'http://localhost:5555/user/secure',
            method: 'GET'

        }, (error, response, body) => {

            const json = JSON.parse(body);
            expect(response.statusCode).toEqual(401);
            expect(json.message).toEqual('Unauthorized');
            done();

        });
    });

    it("should access denied with invalid auth credentials", (done) => {
        request({

            uri: 'http://localhost:5555/user/secure',
            method: 'GET',
            auth: {
                user: 'access',
                pass: 'denied',
                sendImmediately: true
            }

        }, (error, response, body) => {

            const json = JSON.parse(body);
            expect(response.statusCode).toEqual(401);
            expect(json.message).toEqual('Unauthorized');
            done();

        });
    });


    it("should succeed with valid auth credentials", (done) => {
        request({

            uri: 'http://localhost:5555/user/secure',
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

    it("should succeed anonymous inside secured realm without auth credentials", done => {
        request({
            uri: "http://localhost:5555/user/anonymous",
            method: 'GET'
        }, (error, response, body) => {

            expect(response.statusCode).toEqual(200);
            expect(body).toEqual('{"message":"hello mr anonymous"}');
            done();

        });
    });
};