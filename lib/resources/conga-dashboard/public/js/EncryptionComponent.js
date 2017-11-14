import Vue from 'vue';

export default Vue.extend({

    template: `

        <div class="">

            <article class="message is-primary">
                <div class="message-body">
                    Registered Encryption Strategies
                </div>
            </article>

            <p class="is-size-6">
                <strong>{{ total }}</strong> 
                total registered 
                <span v-if="total !== 1">strategies.</span>
                <span v-if="total === 1">strategy.</span>
            </p>

            <span slot="body">
                <table class="table small-text">
                    <thead>
                        <th>ID</th>
                        <th>Algorithm</th>
                        <th>Path</th>
                        <th>Encoding</th>
                        <th>Options</th>
                    </thead>
                    <tbody>
                        <tr v-for="strategy in strategies">
                            <td>{{ strategy.id }}</td>
                            <td>{{ strategy.algo }}</td>
                            <td>{{ strategy.path }}</td>
                            <td>{{ strategy.encoding }}</td>
                            <td>
                                <dl v-for="opt in strategy.options" class="columns">
                                    <dt class="column">{{ opt.key }}</dt>
                                    <dd class="column">{{ opt.value }}</dd>
                                </dl>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </span>

        </div>

    `,

    data: function() {
        return {
            total: 0,
            strategies: []
        }
    },

    created: function() {
        this.$http.get('_conga/api/security/encryption').then((response) => {
            this.total = response.body.total;
            this.strategies = response.body.strategies;
        }, (response) => {

        });
    }
});
