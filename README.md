conga-security
==============


overview
--------

- Automate request authentication
- Restrict access to routes by attached roles.
- Provide services to authenticate and fetch resources (users, accounts, etc).
- Control entity password encryption


configuration
-------------

```
security:
    
    encryption:
        
        user:
            path: demo-bundle:model/user
            algorithm: sha512
            secret: asd8f6ja#*sJHGdfg234jkw@#$%erhg=!
            encode_as_base64: true
        
        admin:
            path: demo-bundle:model/admin
            id: account_encryptor.service.id
        
        protected.data:
            path: demo-bundle:model/protected-data
            algorithm: bcrypt
            saltRounds: 10
            
    
    firewall:
    
        anonymous_access:
            route: ^/my/route/anonymous
            anonymous: true
        
        simple_access_control:
            route: ^/my/route
            roles: ["ROLE_CUSTOM"]
            stateless: false
        
        in_memory_access:
            route: ^/memory
            roles: ROLE_USER
            authenticator: http.authenticator
            provider: memory.provider
        
        api_access_firewall:
            route: ^/api
            authenticator: api.authenticator
            provider: api_client.provider
            stateless: true
            secret: 'auth-token-encryption-key'
        
        html_form_access:
            route: ^/private
            stateless: false
            provider: memory.provider   # any registered provider below
 
            # the encryption options instruct the firewall on how to encrypt and decrypt
            # the auth token when it's saved in a session - for stateful firewalls
            encryption:
                salt: private-session-encryption-salt
                algorithm: 'bf-ecb'  # blowfish
            
            # optionally, the firewall respects some built-in routes
            routes:
                # for stateful firewalls, this route will instruct the firewall processor to
                # remove the matching security realm. it does not destroy the session, it
                # just logs the user out of this realm
                logout:
                    path: /private/logout
                    target: /private/login   # optional redirect target after logout, if not given, redirect is used
 
                # this route allows you to control where to send users to display access denied
                # this options changes the behavior of the firewall - a 302 Found HTTP Status
                # is returned instead of the normal 401 or 403
                redirect: /private/denied
            
            # configure the firewall to use the HTTP Form authenticator
            authenticator:
                service: '@security.firewall.authenticator.http_form'
                
                # the HTTP Form authenticator supports custom configuration
                options:
                    view_route: /private/login                  # (required) the route that shows the login form view
                    action_route: /private/_login               # (required) the route that the form submits to
                    action_failed_route: /private/login/fail    # (optional) the route that the user is redirected to on a failed login attempt
                    success_redirect_route: /private            # (optional) the route that the user should land on when successfully logging in
                    login_field: email                          # (required) the login / username field in the form post data
                    secret_field: password                      # (required) the secret / password field in the form post data
            
            
    authenticators:
    
        http.authenticator: '@security.firewall.authenticator.http_basic'
    
        api.authenticator: '@api.authenticator.service'
    
    providers:
    
        memory.provider:
            memory:
                users:
                    foo:
                        password: foo
                        roles: ROLE_USER
                    bar:
                        password: bar
                        roles: [ROLE_USER, ROLE_ADMIN]
        
        bass.provider:
             bass:
                document: demo-bundle:model/user    # the document path
                login: email                        # the login / username field in the document
                secret: password                    # the password field in the document
        
        api_client.provider: '@api_client.provider.service'
        
        chain.provider: ["memory.provider", "bass.provider"]
```

how it works
------------

When a request is made, a pre controller listener is fired and checks the requested route.  If the 
requested route matches one of the regular expression routes configured in a firewall setting, then 
the request is passed over to the firewall handler for authentication.

The firewall handler will authenticate the request and fetch a resource for the account accessing 
the route from the database or persistence layer.

If the firewall is stateless, all of this will happen on each request.  If the firewall is not 
stateless, the account resource for each firewall is saved in the current session, under its own 
context.  So you can have a session with multiple areas at a time, and the data for each session is 
isolated.

You can think of a firewall as a security realm.

Roles are used to define access to each firewall.  The roles must be attached to the account 
resource returned from the provider.  Each account resource can have one or more roles assigned in 
an array.  You are free to create your own access roles.

security context
----------------

Whether your session has state or not, you can access the authenticated resource from within any 
request scope, using the `security.context` service.

```
const authToken = container.get('security.context').getAuthToken();
const authResource = container.get('security.context').getAuthResource();
```

The resource is the user.  The resource is attached to the token.

authenticators
--------------

The authenticator's purpose is to create and authenticate security tokens.  The authenticator will 
use the provider to fetch an account resource and validate the security credentials attached to the 
request.  If the validation succeeds, the authenticator will return an auth token.

The authenticator needs to be registered as a service.  When you configure the authenticator, you 
provide a reference to the service definition, like so: `@my.authenticator.service`.

Currently, the only built-in supported authenticator is the HTTP Basic Auth authenticator.  This is 
registered as `@security.firewall.authenticator.http_basic`.

You can make your own authenticators, they just need to inherit from 
`@conga/framework-security:security/authenticator/AbstractAuthenticator`.  The AbstractAuthenticator 
takes care of most tasks for you, and you are only required to implement `createToken`, but you 
can overload any method you like, using inheritance.

##### my-bundle:security/MyAuthenticator
```
const { AbstractAuthenticator } = require('@conga/framework-security').Authenticator;
const { PreAuthToken, AuthTokenCredentials } = require('@conga/framework-security').Token;
 
class MyAuthenticator extends AbstractAuthenticator {
    /**
     * Create an authentication token for the current request
     * @param {Object} request The conga request object
     * @param {String} [realm] The realm the token belongs to
     * @returns {Promise}
     */
    createToken(request, realm = 'some-default-security-realm-name') {
        
        // your task is to get the username and password from the request payload / headers
        // and then return a promise with a PreAuthToken having those credentials intact
        
        // if you are expecting a JSON request body, for instance, you could do the following
        
        let username = request.body.username;
        let password = request.body.password;
        
        return Promise.resolve(
            new PreAuthToken(new AuthTokenCredentials(username, password), realm)
        );
    }
}
 
module.exports = MyAuthenticator;
```

##### services.yml
```
services:
 
    my.authenticator.service:
        constructor: "my-bundle:security/MyAuthenticator

```

providers
---------

Providers are used to fetch account resources from their persistence layer or source, such as a 
third party API or a storage layer like MongoDB, Redis, or MySQL, for instance.

There are a couple built-in providers that you can take advantage of, or you can use a service 
as your provider.

The built-in providers allow you to use configuration instead of actually coding your own solutions.

Each built-in provider packaged with this bundle allows you configure an option for logging a user 
out when the password changes.  To use this option, specify `change_password_logout: true` 
inside your provider config.

#### in-memory provider

The In-Memory provider allows you to use your config file as the persistence layer.  The username, 
password, and user roles are all configured inside the provider configuration file, so you do not 
need any other database or file storage.

```
security:

    providers:
    
        admin_memory_provider:
            memory:
                users:
                    super_admin:
                        password: super-admin-password
                        roles: [ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN]
 
                    admin:
                        password: admin-password
                        roles: [ROLE_USER, ROLE_ADMIN]
        
        front_memory_provider:
            memory:
                users:
                    moderator:
                        password: moderator-password
                        roles: [ROLE_USER, ROLE_MODERATOR]
```

In the above example, you can see the password is specified in plain text.  You would do this if 
you are using the 'text' encryptor.  Although, it's advised that you use a salt / pepper, and base64
encode it, if this is your approach.  The username is the object key, `super_admin`, `admin` and 
`moderator`, in this case.

You can specify as many groups of in-memory users as you want, and you can specify as many users in 
each group as you want.   You might separate them into groups so that you can take advantage of 
provider chains, but you can very well just put all users into one group.

You are not restricted to using the text encryptor.  You can use any registered encryptor that you 
wish.  The catch is that you need to encrypt the password yourself and store the encrypted value in 
the config file.  You can use the `conga security:encrypt` command to do this.

The users that get resolved from the In-Memory provider will be an instance of 
`@conga/framework-security:security/user/InMemoryUser`.  This is so that you can configure the 
in-memory user's encryption strategy separately from other user instances.  Below is an example 
using the bcrypt encryptor with the InMemoryUser.

```
security:

    encryption:
    
        # the object key, 'in_memory_user', can be any name you want
        in_memory_user:
 
            # the path to the user class (this must point to InMemoryUser)
            path: @conga/framework-security:security/user/InMemoryUser
 
            # the algorithm you want to use
            algorithm: bcrypt
 
            # bcrypt salt-rounds config
            saltRounds: 50
 
            # application-wide pepper
            pepper: abc123!=!321CBA
```

You can have as many users with different roles and passwords as you wish, but they have to use the 
same encryption strategy, as they are all of the same InMemoryUser class.

After you set up your encryptor, you can generate an encrypted password with the following example:

```
conga security:encrypt --path @conga/framework-security:security/user/InMemoryUser --value admin-password
```

Then copy / paste this password under your user's password property, in your security configuration.

#### bass provider

The bass provider allows you to use any bass adapter as your persistence layer.  Each collection 
(or database table) will have its own document (model), and so each separate user type you want to 
configure should have its own encryption strategy defined.

The bass provider requires that you specify the login and secret field on your document, so that 
the provider knows how to access them.  Currently, methods are not supported, so provide the 
public property name so the provider can reference them correctly.

```
security:
 
    # these are examples, you can use any variation you want
 
    encryption:
    
        administrator:
            path: project-bundle:model/Administrator
            algorithm: bcrypt
            saltRounds: 50
            pepper: TYHJK4%^&238765rtghydjk     # application-wide pepper
        
        user:
            path: project-bundle:model/User
            algorithm: sha512
            pepper: KJHGTYU45678^%$aSFFAf!      # application-wide pepper
            fields:
                salt: encryptionSalt            # grab the salt from the User document so each user has a unique salt!
                secret: encryptionSecret        # grab the hmac secret from the User document so each user has a uniuqe secret!
    
    providers:
    
        admin_user_provider:
            bass:
                document: project-bundle:model/Administrator    # the document path
                login: username                                 # the login / username field in the document
                secret: password                                # the password field in the document
                change_password_logout: true                    # make sure users are logged out on password change
    
        website_user_provider:
            bass:
                document: project-bundle:model/User             # the document path
                login: email                                    # the login / username field in the document
                secret: password                                # the password field in the document
                change_password_logout: true                    # make sure users are logged out on password change
```

In the above configuration, you can see that we have configured two different documents, each with 
their own encryption strategy.

The storage engine / persistence layer can now be managed from within your bass configuration, for 
whichever adapters these documents are registered under (you might have more than one!).

The encrypted passwords live in the row matching the login / secret for each document, inside the 
database.  For that reason, among so many others, it's important that your login / secret 
combination is unique for each user.

#### custom service

You can use your own service as your provider, if you wish.  The only catch is that your service 
must be an instance of a class that inherits from 
`@conga/framework-security:security/provider/AbstractProvider`.

##### my-bundle:service/MyProviderService
```
const { AbstractProvider } = require('@conga/framework-security').Provider;
 
class MyProviderService extends AbstractProvider {
    /**
     * Our example injects the service container
     * @param {Container} container The service container
     **/
    constructor(container) {
        this.container = container;
    }

    /**
     * See if this provider supports a given resource
     * @param {AuthResource|*} resource The resource to check for
     * @returns {boolean}
     */
    supportsResource(resource) {
        // you must implement this method
    }
    
    /**
     * Get the resource that needs to be authenticated
     * @param {*} credentials The secret password / api key, etc.
     * @returns {Promise}
     */
    getResource(credentials) {
        // you must implement this method
    }
    
    /**
     * Refresh an existing resource
     * @param {AuthResource|*} resource
     * @returns {Promise}
     */
    refreshResource(resource) {
        // you must implement this method
    }
}
 
module.exports = MyProviderService;
```

##### services.yml
```
services:
 
    my_provider_service:
        constructor: my-bundle:service/MyProviderService
        arguments: ['@service_container']
```

##### config.yml
```
security:
 
    providers:
     
        my_provider: '@my_provider_service'
    
```

#### chain provider

The chain provider simply allows you to chain multiple providers together.  During authentication,
it will try each provider in the chain, one by one, in series, until it finds one that it can use, 
or until it has tried them all.

```
security:
 
    providers:
    
        # chain the adminstrator access providers together
        admin_chain: [admin_memory_provider, admin_user_provider]
        
        # chain the front-end access providers together
        frontend_chain: [front_memory_provider, website_user_provider, my_provider]
        
        # chain everything together (uses nested chains!)
        chain: [admin_chain, frontend_chain]
```

#### custom built-in providers

If you want to provide your own built-in provider, like the in-memory provider, or the bass 
provider, you can do that. You will need to register your provider with a service tag, and provide 
a method that will be used to check if your provider matches the security configuration.

You might want to do something like this if you are building a bundle for others to use!

##### my-bundle:security/provider-config

You need to create a provider config class that extends AbstractProviderConfig, and tag it in your 
service definition, so that conga-security can register it.

```
const AbstractProviderConfig = require('conga-security').Provider.AbstractProviderConfig;
const MyProvider = require('./provider');
 
class MyProviderConfig extends AbstractProviderConfig {
 
    constructor(container) {
        // if you need it, you can inject the container into your provider configuration
        this.container = container;
    }
    
    // abstract method you are required to provide
    supportsConfig(config) {
 
        // 'bundle_provider' is what we are checking for to see if our provider should be used
        // you can check for ANYTHING that can be configured in your config
 
        return config.bundle_provider instanceof Object;
 
    }
    
    // abstract method you are required to provide
    useConfig(config) {
        return new MyProvider(config);
    }
 
}
 
module.exports = MyProviderConfig;
```

##### my-bundle:security/provider

You need to create a provider class that extends AbstractProvider.  You don't need to register this 
anywhere, your provider config class will return it when `useConfig` is called.

```
const AbstractProvider = require('conga-security').Provider.AbstractProvider;
 
class MyProvider extends AbstractProvider {
 
    // abstract method you are required to provide
    getResource(credentials) {
 
        // this is where you would fetch your resource (user) from a persistence layer or API, etc.
        // return a promise that resolves an AuthResource type
        
        // this example simply returns an AuthUser, which extends AuthResource, with custom roles
 
        const { username, password } = credentials;
        return Promise.resolve(new AuthUser(username, password, ['ROLE_CUSTOM']));
    }
 
}

module.exports = MyProvider;
```

##### services.yml

You need to register your provider config with a service definition and tag it with 
`security.firewall.provider`.

```
services:
 
    bundle.provider:
        constructor: my-bundle:security/provider-config
        arguments: ["@service_container"]
        tags: 
            - { name: security.firewall.provider }
```

##### config.yml

Then you can use your provider by configuring it in your security section in 
`app/config/config.yml`.

```
security:
    
    firewall:
        
        my.firewall:
            route: ^/foo/bar
            authenticator: my.authenticator
            provider: my.provider
    
    providers:
        
        my.provider:
            bundle_provider:
                foo: asdfasdf
                bar: asdfasdf
    
```

#### Nonce Encoding Authentication

All of the built-in providers packaged with this bundle allow you configure nonce encoding for your 
authentication scheme. Nonce encoding allows you to encode the plain-text password with a random / 
unique hash (the nonce), so that the password is not transferred in plain text.

The caveat to this method is that the password needs to be used as is, plain text, whether 
encrypted or not.  As such, it makes sense to use this with the plain text encryptor.

The encoding formula it uses is as follows:

`md5(plain-text-encoded-password_nonce)_nonce`

As you can see, the nonce is included in the MD5 hash, but it is also included in plain text at the 
end of the hash. The server will use the nonce to check the MD5 hash against the plain-text 
password found in the persistence layer. Basically, it creates the hash from the data in the 
persistence layer (the password), and compares it against what is sent up.

Something like this may typically be used for API keys, where you send the API key on each request.

Here are some simple examples encoding the same plain text string with a different nonce.

```
const crypto = require('crypto');
 
const password = 'my-password';
 
let nonce = (new Date()).getTime() + Math.random();
const encoded1 = crypto.createHash('md5').update(password + '_' + nonce).digest('hex') + '_' + nonce;
  
nonce = crypto.createHash('sha1').update((new Date()).getTime() + Math.random().toString()).digest('hex');
const encoded2 = crypto.createHash('md5').update(password + '_' + nonce).digest('hex') + '_' + nonce;
 
console.log(encoded1);  // b4957437333164769e78f855276cedb7_1500065557537.2788
console.log(encoded2);  // 268c9b1473490eb66f76716cbfb94abb_cd35e6bed3cf95f3c5b05e086d0fb73379565247
 
crypto.randomBytes(15, (err, buff) => {
    if (err) {
        throw err;
    }
    const nonce = buff.toString('hex');
    const encoded = crypto.createHash('md5').update(password + '_' + nonce).digest('hex') + '_' + nonce;
    console.log(encoded);   // f476de4d477466f07540788021f94c43_b5a4d025ffa02d0db7c2bdc97311a3
});
```

To use this configuration option, specify `nonce_encoded: true` in your provider configuration.

```
security:
 
    encryption:
        
        # use the plain-text encryptor for nonce_encoding
        api-client:
            path: demo-bundle:model/ApiClient
            algorithm: text
 
    providers:
    
        bass.provider:
             bass:
                document: demo-bundle:model/ApiClient   # the document path
                login: publicKey                        # the login / username field in the document
                secret: secretKey                       # the password field in the document
                nonce_encoded: true                     # use nonce-encoding
```

encryption
----------

Encryptors get mapped to a class path and instruct the system on how to encrypt and compare secure 
keys for that class.

#### config.yml

```
security:

    encryption:
    
        my_user:
            path: conga-security:security/user/AuthUser
            
            algorithm: bcrypt
            saltRounds: 50
            
            salt: application-wide-salt
            pepper: application-wide-pepper
            
            encode_as_base64: true
            
            fields:
                salt: secretSalt
            
            methods:
                salt: getSecretSalt
```

No matter what algorithm you use, they all support some common configuration options.

`algorithm` - Specifies which encryption algorithm to use.  It must be a registered algorithm.

`salt` - Allows you to provide an application wide salt to all strings before they get encrypted.

`pepper` - Allows you to provide an application wide pepper to all strings before they get 
encrypted.

`encode_as_base64` - Specifies whether you want the encrypted value to be base64 encoded also.

`fields` - Allows you to map values from resource fields.  If `fields.salt` is provided, that value 
is used instead of `salt`. 

`methods` - Allows you to map values from resource methods. If any methods return a value, that 
value is mapped into `fields` automatically for you.

#### algorithms

There are different algorithms you can use.  Algorithms are defined as a service definition and 
tagged as a security encryptor.  

You can define your own algorithms as you wish.  Your encryptor should inherit from 
`conga-security:security/encryption/AbstractEncryptor` to make things easier, but it doesn't have 
to.  You just need to provide an `encrypt` and `compare` method.

Below are a few taken from the encryption.yml file packaged with this module.

```
    security.encryption.plain_text:
        constructor: conga-security:security/encryption/PlainTextEncryptor
        tags:
            - { name: security.encryptor, algorithm: text }
    
    security.encryption.md5:
        constructor: conga-security:security/encryption/CryptoHmacEncryptor
        arguments: ["md5"]
        tags:
            - { name: security.encryptor, algorithm: md5 }
    
    security.encryption.sha512:
        constructor: conga-security:security/encryption/CryptoHmacEncryptor
        arguments: ["sha512"]
        tags:
            - { name: security.encryptor, algorithm: sha512 }
```

There are only a hand full of algorithms supported by default:

- text
- bcrypt
- sha256
- sha512
- md5

There is a common library you can use for Hmac encryption, which can use any supported algorithm.  
sha256, sha512, and md5 use it.

##### algorithm configuration

Each algorithm may allow you to provide additional configuration.  This configuration can be mapped 
fields or static values.

The `hmac encryptors` want you to specify a secret.  That secret can be application wide, specified 
in the config, or it can be read from a resource. 

The `bcrypt encryptor` wants you to specify a salt or saltRounds.

The entire configuration is passed to the encryptor when it is instantiated.

For example:
```
security:

    encryption:
    
        my_user:
            path: my-bundle:model/User
            algorithm: sha512
            pepper: 123456!!!
            encode_as_base64: true
            methods:
                salt: getSalt
                secret: getSecret
```

The above configuration says to use the `sha512` encryption algorithm, but apply a pepper, salt, 
and a secret to it. The salt and the secret live on the resource itself, so each one is unique.

If your password was `test` and the user salt was `123`, then the actual value that gets encrypted 
would be `123456!!!123test`.

##### encryptor as a service

If you don't want to register an encryptor, you can define it as a service and specify the service 
id.

#### encryption service

There is a service provided, `security.encryption` that will handle this for any mapped instance 
type.

```
container.get('security.encryption').encrypt(instance, 'something to encrypt').then(encrypted => {

    console.log('the encrypted value is', encrypted);

});
```
#### encryption command

There is a command that you can use to encrypt and compare an encrypted string.

```
$ conga security:encrypt --path conga-security:security/user/AuthUser --value encrypt_this --compare already_encrypted
```

You can run help on the command to read about its options.

```
$ conga security:encrypt --help
```
