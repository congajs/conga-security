const Controller = require('@conga/framework').Controller;

/**
 *
 * @Route("/annotation")
 *
 * @Firewall(realm="annotation_firewall",
 *           roles=["ROLE_ANNOTATION"],
 *           stateless=true,
 *           authenticator="http.authenticator",
 *           provider="access.provider")
 */
module.exports = class AnnotationController extends Controller {

    /**
     * @Route("/secure", methods=["GET"])
     */
    secure(req, res) {
        res.return({message: 'got in'});
    }

    /**
     * @Route("/anonymous", methods=["GET"])
     *
     * @Firewall(realm="annotation_anonymous_firewall", anonymous="true")
     *
     */
    anonymous(req, res) {
        res.return({message: 'hello mr anonymous'});
    }

};
