conga-security [![Build Status](https://secure.travis-ci.org/congajs/conga-security.png)](http://travis-ci.org/congajs/conga-security)
==============

The security bundle allows you to create firewalls that control access to your controllers, and 
configure encryption algorithms for your application.

- Automate request authentication
- Restrict access to routes by attached roles.
- Provide services to authenticate and fetch resources (users, accounts, etc).
- Control entity password encryption

See the [documentation](/docs) for more information.


Configuration
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