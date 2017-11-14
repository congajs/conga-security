export default [

    {
        name: "security",
        path: "/security",
        component: require('./SecurityComponent').default,

        children: [
            {
                name: 'security',
                path: '',
                component: require('./FirewallComponent').default
            },
            {
                name: 'security.encryption',
                path: '/security/encryption',
                component: require('./EncryptionComponent').default
            },
            {
                name: 'security.authenticators',
                path: '/security/authenticators',
                component: require('./AuthenticatorComponent').default
            },
            {
                name: 'security.providers',
                path: '/security/providers',
                component: require('./ProviderComponent').default
            }
        ]
    }

];
