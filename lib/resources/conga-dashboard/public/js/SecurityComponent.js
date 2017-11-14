import Vue from 'vue';

export default Vue.extend({

    template: `
        <div>

            <hero>

                <span slot="hero-title">{{ title }}</span>
                <span slot="hero-subtitle">{{ subtitle }}</span>

                <div class="container" slot="hero-foot">

                    <tab-container>
                        <tab route="security" label="Firewall"></tab>
                        <tab route="security.encryption" label="Encryption"></tab>
                        <tab route="security.authenticators" label="Authenticators"></tab>
                        <tab route="security.providers" label="Providers"></tab>
                    </tab-container>

                </div>

            </hero>

            <main-section>

                <div class="content">
                    <router-view></router-view>
                </div>

            </main-section>

        </div>
    `,

    data: function() {
        const meta = BUNDLE_METAS.reduce((data, meta) => meta.id === 'security' ? data || meta : data, null);
        return {
            title: meta.name,
            subtitle: meta.bundle
        };
    },

    components: {
        //'navbar-component': NavbarComponent
    }
});
