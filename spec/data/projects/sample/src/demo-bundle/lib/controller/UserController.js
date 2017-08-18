const Controller = require('@conga/framework').Controller;

/**
 * @Route("/user")
 */
module.exports = class UserController extends Controller {

    /**
     * @Route("/secure", methods=["GET"])
     */
    secure(req, res) {
        res.return({message: 'got in'});
    }

    /**
     * @Route("/anonymous", methods=["GET"])
     */
    anonymous(req, res) {
        res.return({message: 'hello mr anonymous'});
    }

};
