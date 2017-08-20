const Controller = require('@conga/framework').Controller;

/**
 * @Route("/auth/http-form")
 */
module.exports = class AuthHttpFormController extends Controller {

    /**
     * @Route("/_login", name="login.action", methods=["POST"])
     * @Route("/login", name="login", methods=["GET"])
     * @Route("/login/:failed", name="login.action.failed", methods=["GET"])
     */
    login(req, res) {
        res.return({message: 'got login', failed: req.params.failed === 'failed'});
    }

    /**
     * @Route("/logout", name="logout", methods=["GET"])
     */
    logout(req, res) {
        res.return({message: 'should be redirected'});
    }

    /**
     * @Route("/denied", name="denied", methods=["GET"])
     */
    denied(req, res) {
        res.return({message: 'got denied'});
    }

    /**
     * @Route("/access-granted", name="granted", methods=["GET"])
     */
    granted(req, res) {
        res.return({message: 'got access granted'});
    }

};
