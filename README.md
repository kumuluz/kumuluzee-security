# KumuluzEE Security
[![Build Status](https://img.shields.io/travis/kumuluz/kumuluzee-security/master.svg?style=flat)](https://travis-ci.org/kumuluz/kumuluzee-security)

> KumuluzEE Security extension for the Kumuluz EE microservice framework. 

KumuluzEE Security is a security project for the KumuluzEE microservice framework. It provides support for OpenID 
authentication through standard Java EE security annotations for roles. It is specifically targeted towards securing 
REST services. Roles are mapped to the selected OpenID provider. KumuluzEE Security has been designed to work with 
different OpenID providers. Currently only Keycloak is supported. Contributions for other OpenID providers are welcome.

## Usage

You can enable the KumuluzEE Security authentication with Keycloak by adding the following dependencies:

```xml
<dependency>
    <groupId>com.kumuluz.ee.security</groupId>
    <artifactId>kumuluzee-security-keycloak</artifactId>
    <version>${kumuluzee-security.version}</version>
</dependency>
<dependency>
    <groupId>org.keycloak</groupId>
    <artifactId>keycloak-jetty94-adapter</artifactId>
    <version>${keycloak.version}</version>
</dependency>
```

The `keycloak.version` property should match the version of keycloak that is used.

### Security configuration

To protect a REST service using KumuluzEE Security authentication you have to annotate the REST application class with 
the `@DeclareRoles` annotation. When using the `@DeclareRoles` annotation the Keycloak configuration (**keycloak.json**) 
has to be provided with configuration key `kumuluzee.security.keycloak.json`. The configuration key can be defined as 
an environment variable, file property or config server entry (if using the KumuluzEE Config project with support for 
etcd/Consul). Please refer to KumuluzEE Config for more information. Optionally you can also provide the configuration 
in code using the `@Keycloak` annotation. 

Example of configuration with **keycloak.json** as string value:
```yaml
security:
    keycloak:
        json: '{
            "realm": "master",
            "bearer-only": true,
            "auth-server-url": "http://localhost:8082/auth",
            "ssl-required": "external",
            "resource": "customers-api",
            "confidential-port": 0
        }'
```

Using **keycloak.json** fields directly in yaml is also supported:
```yaml
security:
    keycloak:
      realm: "master"
      bearer-only: true
      auth-server-url: "http://localhost:8082/auth"
      ssl-required: "external"
      resource: "customers-api"
```

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
transform Keycloak roles into internal application roles. Role mappings are defined using the `kumuluzee.security.roles`
key.

Example role mapping configuration:
```yaml
kumuluzee:
  security:
    roles:
      user: role_user
      admin: role_admin
```

You may also disable Jetty servlet security, which is enabled by default, by setting key `kumuluzee.security.disable-jetty-auth` to `true`.

You can set a custom config resolver class (see [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#config_external_adapter)) to be able to tweak Keycloak configuration at runtime for each request (for multitenant or purposes). Note that this class must implement `org.keycloak.adapters.KeycloakConfigResolver`.

Example custom config resolver configuration:
```yaml
kumuluzee:
  security:
    keycloak:
      config-resolver: foo.bar.MyKeycloakConfigResolver
```

## Realm and client based roles

By default, realm roles are evaluated and client roles are ignored. You can change the configuration to use client roles instead by using `roles-from-resources` config key and an array of clients.
```yaml
security:
    keycloak:
      roles-from-resources:
        - "customers-api"
```

It is not possible to evaluate realm and client roles at the same time since `@RolesAllowed` accepts a plain string and has no knowledge of role origin. The choice is exclusive.

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
