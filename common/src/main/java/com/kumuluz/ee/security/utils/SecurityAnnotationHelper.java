package com.kumuluz.ee.security.utils;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Benjamin Kastelic
 */
public class SecurityAnnotationHelper {

    public final static String SECURITY_PROCESSED = "com.kumuluz.ee.security.processed";

    public static Object getSecurityAnnotation(Method method) {
        if (method.getAnnotation(DenyAll.class) != null) // method level @DenyAll annotation
            return method.getAnnotation(DenyAll.class);
        if (method.getAnnotation(RolesAllowed.class) != null) // method level @RolesAllowed annotation
            return method.getAnnotation(RolesAllowed.class);
        if (method.getAnnotation(PermitAll.class) != null) // method level @PermitAll annotation
            return method.getAnnotation(PermitAll.class);
        if (method.getAnnotation(DenyAll.class) != null) // class level @DenyAll annotation
            return method.getAnnotation(DenyAll.class);
        if (method.getAnnotation(RolesAllowed.class) != null) // class level @RolesAllowed annotation
            return method.getAnnotation(RolesAllowed.class);
        if (method.getAnnotation(PermitAll.class) != null) // class level @PermitAll annotation
            return method.getAnnotation(PermitAll.class);

        return null; // no security annotation present
    }

    public static List<String> getRolesAllowed(Method method) {
        List<String> rolesAllowed = new ArrayList<>();

        RolesAllowed rolesAllowedAnnotation = method.getAnnotation(RolesAllowed.class) != null
                ? method.getAnnotation(RolesAllowed.class)
                : method.getDeclaringClass().getAnnotation(RolesAllowed.class);

        if (rolesAllowedAnnotation != null) {
            rolesAllowed = Arrays.asList(rolesAllowedAnnotation.value());
        }

        return rolesAllowed;
    }
}
