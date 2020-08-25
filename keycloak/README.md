# KumuluzEE Security Keycloak
[![Maven Central](https://img.shields.io/maven-central/v/com.kumuluz.ee.security/kumuluzee-security-keycloak)](https://mvnrepository.com/artifact/com.kumuluz.ee.security/kumuluzee-security-keycloak)
> KumuluzEE Security extension for the Keycloak authentication server

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

The `keycloak.version` property should match the version of Keycloak Server that is used.

## Keycloak configuration

Keycloak configuration (**keycloak.json**) 
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



