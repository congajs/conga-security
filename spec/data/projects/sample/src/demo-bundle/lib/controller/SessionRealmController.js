const { Controller } = require('@conga/framework');

/**
 *
 * @Route("/session/realm")
 */
module.exports = class SessionRealmController extends Controller {
    /**
     * @Route("/:realm/set", name="realm_set", methods=["GET"])
     */
    realmSet(req, res) {
        const realm = this.container.get('security.context').getRealm();
        req.session.session_global = 'Hi! I am a global variable!';
        req.session.set('session_realm', 'The session realm is ' + realm);
        res.return({
            realm,
            requestRealm: req.params.realm,
            sessionValue: req.session.get('session_realm'),
            globalValue: req.session.get('session_global'),
            keys: req.session.keys(),
            data: req.session.data()
        });
    }

    /**
     * @Route("/:realm/get", name="realm_get", methods=["GET"])
     */
    realmGet(req, res) {
        const realm = this.container.get('security.context').getRealm();
        res.return({
            realm,
            requestRealm: req.params.realm,
            sessionValue: req.session.get('session_realm'),
            globalValue: req.session.get('session_global'),
            keys: req.session.keys(),
            data: req.session.data()
        });
    }
};