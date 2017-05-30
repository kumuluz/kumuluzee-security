# KumuluzEE Security
[![Build Status](https://img.shields.io/travis/kumuluz/kumuluzee-security/master.svg?style=flat)](https://travis-ci.org/kumuluz/kumuluzee-security)

> KumuluzEE Security extension for the Kumuluz EE microservice framework. 

KumuluzEE Security is a security extension for the KumuluzEE microservice framework. It provides support for OpenID authentication through standard Java EE security annotations for roles. It is specifically targeted towards securing REST services. Roles are mapped to the selected OpenID provider.   
KumuluzEE Security has been designed to work with different OpenID providers. Currently, Keycloak is supported. Contributions for other OpenID providers are welcome.

## Usage

You can enable the KumuluzEE Security authentication with Keycloak by adding the following dependency:
```xml
<dependency>
    <groupId>com.kumuluz.ee.security</groupId>
    <artifactId>kumuluzee-security-keycloak</artifactId>
    <version>${kumuluzee-security.version}</version>
</dependency>
```

### Security configuration

To protect a REST service using KumuluzEE Security authentication you have to annotate the REST application class with the `@DeclareRoles` annotation. When using the `@DeclareRoles` annotation the Keycloak configuration (**keycloak.json**) has to be
provided with configuration key `kumuluzee.security.keycloak.json`. The configuration key can be defined as an environment variable, file property or config server entry (if using the KumuluzEE Config extension with support for etcd/Consul). Please refer to KumuluzEE Config for more information. 
Optionally you can override the configuration in the code using the `@Keycloak`
annotation. 

Example of security configuration with configuration override:
```java
@DeclareRoles({"user", "admin"})
@Keycloak(json =
        "{" +
        "  \"realm\": \"customers\"," +
        "  \"bearer-only\": true," +
        "  \"auth-server-url\": \"https://localhost:8082/auth\"," +
        "  \"ssl-required\": \"external\"," +
        "  \"resource\": \"customers-api\"" +
        "}"
)
@ApplicationPath("v1")
public class CustomerApplication extends Application {
}
```

It is possible to specify security constraints for JAX-RS resources using the standard `@DenyAll`, `@PermitAll` and
`@RolesAllowed` Java annotations.
 
 Example of security constraints:
 ```java
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Path("customers")
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

The security extension also supports CDI based security, which means that security constraints are checked and resolved 
during method invocation. To enable CDI based security just add `@Secured` annotation to the CDI bean and use the 
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

**NOTE**: When using the security constraint annotations note that these constraints behave as if they were declared in 
the **web.xml** descriptor, i.e. the url patterns do not support path parameters. 

## Changelog
<!--- TODO --->

## Contribute
<!--- TODO --->

## License

MIT
