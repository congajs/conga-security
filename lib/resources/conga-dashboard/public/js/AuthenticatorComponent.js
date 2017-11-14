import Vue from 'vue';

export default Vue.extend({

    template: `

        <div class="">

            <article class="message is-primary">
                <div class="message-body">
                    Registered Security Authenticators
                </div>
            </article>

            <p class="is-size-6">
                <strong>{{ total }}</strong> 
                total registered authenticator<span v-if="total !== 1">s</span>.
            </p>


            <table class="table small-text">
                <thead>
                    <th>ID</th>
                    <th>Service</th>
                    <th>Firewalls</th>
                </thead>
                <tbody>
                    <tr v-for="authenticator in authenticators">
                        <td>{{ authenticator.id }}</td>
                        <td>{{ authenticator.service }}</td>
                        <td>
                            <div v-if="authenticator.firewalls.length === 0" 
                                class="has-text-danger">Not Used</div>
                            <div v-for="firewall in authenticator.firewalls">{{ firewall }}</div>
                        </td>
                    </tr>
                </tbody>
            </table>

        </div>

    `,

    data: function() {
        return {
            total: 0,
            authenticators: []
        }
    },

    created: function() {
        this.$http.get('_conga/api/security/authenticators').then((response) => {
            this.total = response.body.total;
            this.authenticators = response.body.authenticators;
        }, (response) => {

        });
    }
});
