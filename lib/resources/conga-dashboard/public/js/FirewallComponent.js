import Vue from 'vue';

export default Vue.extend({

    template: `

        <div class="">

            <article class="message is-primary">
                <div class="message-body">
                    Registered Security Firewalls
                </div>
            </article>

            <p class="is-size-6">
                <strong>{{ total }}</strong> 
                total registered firewall<span v-if="total !== 1">s</span>.
            </p>


            <table class="table small-text">
                <thead>
                    <th>Name</th>
                    <th>Route</th>
                    <th>Stateless</th>
                    <th>Roles</th>
                    <th>Authenticator</th>
                    <th>Provider</th>
                </thead>
                <tbody>
                    <tr v-for="firewall in firewalls">
                        <td>{{ firewall.id }}</td>
                        <td>{{ firewall.route }}</td>
                        <td>{{ firewall.stateless ? 'Stateless' : 'No' }}</td>
                        <td>
                            <div v-if="firewall.anonymous" class="has-text-danger">anonymous</div>
                            <div v-else>
                                <p v-for="role in firewall.roles">{{ role }}</p>
                            </div>
                        </td>
                        <td>{{ firewall.authenticator.key }}</td>
                        <td>{{ firewall.provider }}</td>
                    </tr>
                </tbody>
            </table>

        </div>

    `,

    data: function() {
        return {
            total: 0,
            firewalls: []
        }
    },

    created: function() {
        this.$http.get('_conga/api/security/firewall').then((response) => {
            this.total = response.body.total;
            this.firewalls = response.body.firewalls;
        }, (response) => {

        });
    }
});
