package com.kumuluz.ee.security.annotations;

import javax.enterprise.util.Nonbinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for Keycloak security configuration.
 *
 * @author Benjamin Kastelic
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Keycloak {
    @Nonbinding String json() default "";
    @Nonbinding String authServerUrl() default "";
    @Nonbinding String sslRequired() default "";
}
