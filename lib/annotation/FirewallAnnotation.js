/*
 * This file is part of the conga-security module.
 *
 * (c) Anthony Matarazzo <email@anthonymatarazzo.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// framework libs
const Annotation = require('@conga/annotations').Annotation;

/**
 * The @Firewall annotation creates firewalls for each route it's mapped to.
 *
 * If the annotation is applied to a controller's definition, it is mapped to each route in the controller.
 * If the annotation is applied to a controller's action method, it is mapped to that route for that action.
 *
 * ex. @Firewall(realm="secure_realm",
 *               roles=["ROLE_USER"],
 *               authenticator="http.authenticator",
 *               provider="memory.provider")
 *
 */
class FirewallAnnotation extends Annotation {
    /**
     * {@inheritdoc}
     */
    static get annotation() { return 'Firewall'; }

    /**
     * {@inheritdoc}
     */
    static get targets() { return [Annotation.DEFINITION, Annotation.PROPERTY] }
}

module.exports = FirewallAnnotation;
