const Controller = require('@conga/framework').Controller;

/**
 * @Route("/auth/http-form")
 */
module.exports = class AuthHttpFormController extends Controller {

    /**
     * @Route("/login", methods=["GET"])
     * @Route("/_login", methods=["POST"])
     */
    login(req, res) {
        res.return({message: 'got login'});
    }

    /**
     * @Route("/denied", methods=["GET"])
     */
    denied(req, res) {
        res.return({message: 'got denied'});
    }

    /**
     * @Route("/access-granted", methods=["GET"])
     */
    granted(req, res) {
        res.return({message: 'got access granted'});
    }

};
