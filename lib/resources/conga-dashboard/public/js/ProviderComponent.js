import Vue from 'vue';

export default Vue.extend({

    template: `

        <div class="">

            <article class="message is-primary">
                <div class="message-body">
                    Registered Security Providers
                </div>
            </article>

            <p class="is-size-6">
                <strong>{{ total }}</strong> 
                total registered provider<span v-if="total !== 1">s</span>.
            </p>


            <table class="table small-text">
                <thead>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Firewalls</th>
                    <th>Value</th>
                </thead>
                <tbody>
                    <tr v-for="provider in providers">
                        <td>{{ provider.id }}</td>
                        <td>{{ provider.type }}</td>
                        <td>
                            <div v-if="provider.firewalls.length === 0" class="has-text-danger">
                                Not Used
                            </div>
                            <div v-for="firewall in provider.firewalls">{{ firewall }}</div>
                        </td>
                        <td>
                            <span v-if="provider.type === 'Service'">{{ provider.value }}</span>
                            <span v-if="provider.type !== 'Service'">
                                <pre style="background-color:transparent; cursor:default;">
                                    <code class="lang-javascript">{{ provider.value }}</code>
                                </pre>
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>

        </div>

    `,

    data: function() {
        return {
            total: 0,
            providers: []
        }
    },

    created: function() {
        this.$http.get('_conga/api/security/providers').then((response) => {
            this.total = response.body.total;
            this.providers = response.body.providers;
        }, (response) => {

        });
    },

    updated: function() {
        window.hljs.initHighlighting.called = false;
        window.hljs.initHighlighting();
    }
});
