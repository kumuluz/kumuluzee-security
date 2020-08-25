# KumuluzEE Security Firebase
[![Maven Central](https://img.shields.io/maven-central/v/com.kumuluz.ee.security/kumuluzee-security-firebase)](https://mvnrepository.com/artifact/com.kumuluz.ee.security/kumuluzee-security-firebase)
> KumuluzEE Security extension for the Firebase Authentication service

## Usage

You can enable the KumuluzEE Security authentication with Firebase by adding the following dependencies:

```xml
<dependency>
    <groupId>com.kumuluz.ee.security</groupId>
    <artifactId>kumuluzee-security-firebase</artifactId>
    <version>${kumuluzee-security.version}</version>
</dependency>
```

## Firebase configuration

### Credentials

KumuluzEE Security Firebase uses Firebase's Admin SDK underneath, which expects us to provide json file with credentials
where environment variable `GOOGLE_APPLICATION_CREDENTIALS` must be set to the path of valid google-credentials.json. [More](https://firebase.google.com/docs/admin/setup#initialize-sdk).

### Roles

In order to limit access to endpoints for users with a certain role, you need to add roles to a user, by setting additional claims to the Firebase user. Instructions for supported
platforms can be found in [Firebase docs](https://firebase.google.com/docs/auth/admin/custom-claims). Specified role claim must have format of array of strings. 

In order to set name of the claim used for roles, we can provide a configuration entry with key `kumuluzee.security.firebase.role-claim`, which defaults to `roles`.

### Verified users
Firebase, by default ignores user email validity. If we want to limit access only to users with verified email, we can provide
a configuration entry with key `kumuluzee.security.firebase.only-verified-email` to `true` (defaults to `false`).
