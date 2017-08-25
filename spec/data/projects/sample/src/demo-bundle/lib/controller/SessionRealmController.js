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
        const username = this.container.get('security.context').getAuthToken().credentials.login;
        req.session.session_global = 'Hi! I am a global variable!';
        req.session.set('session_realm', 'The session realm is ' + realm);
        res.return({
            realm,
            username,
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
        const username = this.container.get('security.context').getAuthToken().credentials.login;
        res.return({
            realm,
            username,
            requestRealm: req.params.realm,
            sessionValue: req.session.get('session_realm'),
            globalValue: req.session.get('session_global'),
            keys: req.session.keys(),
            data: req.session.data()
        });
    }

    /**
     * @Route("/:realm/logout", name="realm_logout", methods=["GET"])
     */
    realmLogout(req, res) {
        res.return({
            message: 'Logged Out',
            data: req.session.data(),
            realm: this.container.get('security.context').getRealm(),
        });
    }
};