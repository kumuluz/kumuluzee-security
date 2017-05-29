package com.kumuluz.ee.security.annotations;

import javax.annotation.Priority;
import javax.enterprise.util.Nonbinding;
import javax.interceptor.InterceptorBinding;
import java.lang.annotation.*;

/**
 * Custom RolesAllowed annotation. Behaves just like the standard Java RolesAllowed annotation.
 *
 * @author Benjamin Kastelic
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RolesAllowed {
    @Nonbinding String[] value() default "";
}
