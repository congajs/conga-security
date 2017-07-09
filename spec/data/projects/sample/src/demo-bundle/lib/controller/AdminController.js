const Controller = require('@conga/framework').Controller;

/**
 * @Route("/admin")
 */
module.exports = class AdminController extends Controller {

    /**
     * @Route("/secure", methods=["GET"])
     */
    secure(req, res) {
        res.return({message: 'got in'});
    }

}
