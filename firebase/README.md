# KumuluzEE Security Firebase
[![Maven Central](https://img.shields.io/maven-central/v/com.kumuluz.ee.security/kumuluzee-security-firebase)](https://mvnrepository.com/artifact/com.kumuluz.ee.security/kumuluzee-security-firebase)
> KumuluzEE Security extension for the Firebase Authentication service

## Setup

You can enable the KumuluzEE Security authentication with Firebase by adding the following dependencies:

```xml
<dependency>
    <groupId>com.kumuluz.ee.security</groupId>
    <artifactId>kumuluzee-security-firebase</artifactId>
    <version>${kumuluzee-security.version}</version>
</dependency>
```

## Firebase configuration

### Google credentials setup

KumuluzEE Security Firebase uses Firebase's Admin SDK underneath, which expects us to provide json file with credentials
where environment variable `GOOGLE_APPLICATION_CREDENTIALS` must be set to the path of valid google-credentials.json. [More](https://firebase.google.com/docs/admin/setup#initialize-sdk).

## Usage

### Validating credentials

Library will first check for ID token in `Authorization` header (bearer credentials).

Alternatively, you can also enable checking session cookie. To do that, enable checking session cookie, by setting key 
`kumuluzee.security.firebase.session.enabled` to `true` (defaults to `false`). Note, that library will always first check
for presence of ID token, even if session check is enabled.

### Roles

In order to limit access to endpoints for users with a certain role, you need to add roles to a user, by setting additional claims to the Firebase user. Instructions for supported
platforms can be found in [Firebase docs](https://firebase.google.com/docs/auth/admin/custom-claims). Specified role claim must have format of array of strings. 

In order to set name of the claim used for roles, we can provide a configuration entry with key `kumuluzee.security.firebase.role-claim`, which defaults to `roles`.

### Verified users
Firebase, by default ignores user email validity. If we want to limit access only to users with verified email, we can provide
a configuration entry with key `kumuluzee.security.firebase.only-verified-email` to `true` (defaults to `false`).

### Check token revocation
If `kumuluzee.security.firebase.check-revoked` is set to `true` (defaults to `false`), 
Firebase will perform an additional check to see if the ID token has been revoked since it was issued. Beware, that this option requires making an additional remote API call.

If you are using session cookie, you can also specify to check revocation, specifically for session cookies, by 
setting key `kumuluzee.security.firebase.session.check-revoked` to `true` (defaults to `false`). If this key is not set, it will 
default to value of `kumuluzee.security.firebase.check-revoked`.

### Session cookies

By default, library will check for cookie with name of `session`. To change this to custom value, set key `kumuluzee.security.firebase.session.cookie.name`.

## Example configuration

Example of all possible configuration keys with their default values:

```yaml
kumuluzee:
  security:
    firebase:
      role-claim: roles
      only-verified-email: false
      check-revoked: false
      session:
        enabled: false
        check-revoked: false
        cookie:
          name: session
```