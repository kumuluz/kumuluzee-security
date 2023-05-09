# KumuluzEE Security
[![KumuluzEE CI](https://github.com/kumuluz/kumuluzee-security/actions/workflows/kumuluzee-ci.yml/badge.svg)](https://github.com/kumuluz/kumuluzee-security/actions/workflows/kumuluzee-ci.yml)

> KumuluzEE Security extension for the Kumuluz EE microservice framework. 

KumuluzEE Security is a security project for the KumuluzEE microservice framework. It provides support for OpenID 
authentication through standard Java EE security annotations for roles. It is specifically targeted towards securing 
REST services. Roles are mapped to the selected OpenID provider. KumuluzEE Security has been designed to work with 
different OpenID providers. 

## Providers

Currently, the following providers are supported:
* [Keycloak](/keycloak/README.md)
* [Firebase](/firebase/README.md)

Contributions for other OpenID providers are welcome.

## Security configuration

To protect a REST service using KumuluzEE Security authentication you have to annotate the REST application class with 
the `@DeclareRoles` annotation:
````java
@DeclareRoles({"role1", "role2"})
public class RestApplication extends Application {
    
}
````

Alternatively, you can also annotate it with `@Keycloak` or `@FirebaseAuth`.


It is possible to specify security constraints for JAX-RS resources using the standard `@DenyAll`, `@PermitAll` and
`@RolesAllowed` Java annotations.
 
Example of security constraints:
 ```java
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Path("customers")
@Secure
public class CustomerResource {

    @GET
    @Path("{customerId}")
    @PermitAll
    public Response getCustomer(@PathParam("customerId") String customerId) {
        ...
    }

    @POST
    @RolesAllowed("user")
    public Response addNewCustomer(Customer customer) {
        ...
    }
}
```

**NOTE**: When using the non CDI security constraint annotations, note that these constraints behave as if they were 
declared in the **web.xml** descriptor, i.e. the url patterns do not support path parameters.

The security extension also supports CDI based security, which means that security constraints are checked and resolved 
during method invocation. To enable CDI based security just add `@Secure` annotation to the CDI bean and use the 
standard Java security annotations as before.

Example of CDI based security:
```java
@RequestScoped
@Secure
@PermitAll
public class CustomerResource {

    @RolesAllowed("user")
    public Customer getCustomer(String customerId) {
        ...
    }

    @RolesAllowed("admin")
    public void addNewCustomer(Customer customer) {
        ...
    }
}
``` 

When using the CDI based security it is also possible to provide application role mappings. The specified role mappings 
transform provider roles into internal application roles. Role mappings are defined using the `kumuluzee.security.roles`
key.

Example role mapping configuration:
```yaml
kumuluzee:
  security:
    roles:
      user: role_user # 'user' from provider will be mapped to 'role_user' in this service
      admin: role_admin
```

## Additional configuration

You may also disable Jetty servlet security, which is enabled by default, by setting key `kumuluzee.security.disable-jetty-auth` to `true`.

## Changelog

Recent changes can be viewed on Github on the [Releases Page](https://github.com/kumuluz/kumuluzee-security/releases)

## Contribute

See the [contributing docs](https://github.com/kumuluz/kumuluzee-security/blob/master/CONTRIBUTING.md)

When submitting an issue, please follow the 
[guidelines](https://github.com/kumuluz/kumuluzee-security/blob/master/CONTRIBUTING.md#bugs).

When submitting a bugfix, write a test that exposes the bug and fails before applying your fix. Submit the test 
alongside the fix.

When submitting a new feature, add tests that cover the feature.

## License

MIT
