package com.kumuluz.ee.security.annotations;

import javax.enterprise.util.Nonbinding;
import javax.interceptor.InterceptorBinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Custom DeclareRoles annotation. Behaves just like the standard Java DeclareRoles annotation.
 *
 * @author Benjamin Kastelic
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface DeclareRoles {
    @Nonbinding String[] value() default "";
}
