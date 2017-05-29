package com.kumuluz.ee.security.utils;

import com.kumuluz.ee.security.annotations.DenyAll;
import com.kumuluz.ee.security.annotations.PermitAll;
import com.kumuluz.ee.security.annotations.RolesAllowed;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Benjamin on 29. maj 2017.
 */
public class SecurityAnnotationHelper {

    public final static String SECURITY_PROCESSED = "com.kumuluz.ee.security.processed";

    public static boolean hasDenyAllOverride(Method method) {
        return method.getAnnotation(DenyAll.class) != null;
    }

    public static boolean hasRolesAllowedOverride(Method method) {
        return method.getAnnotation(RolesAllowed.class) != null;
    }

    public static boolean hasPermitAllOverride(Method method) {
        return method.getAnnotation(PermitAll.class) != null;
    }

    public static List<String> getRolesAllowed(InvocationContext context) {
        List<String> rolesAllowed = new ArrayList<>();

        RolesAllowed rolesAllowedAnnotation = context.getMethod().getAnnotation(RolesAllowed.class) != null
                ? context.getMethod().getAnnotation(RolesAllowed.class)
                : context.getMethod().getDeclaringClass().getAnnotation(RolesAllowed.class);

        if (rolesAllowedAnnotation != null) {
            rolesAllowed = Arrays.asList(rolesAllowedAnnotation.value());
        }

        return rolesAllowed;
    }

    public static void setSecurityProcessed(InvocationContext context) {
        if (context.getContextData() != null) {
            context.getContextData().put(SECURITY_PROCESSED, "true");
        }
    }

    public static boolean isSecurityProcessed(InvocationContext context) {
        if (context.getContextData() != null) {
            Object value = context.getContextData().get(SECURITY_PROCESSED);
            return value != null && value.equals("true");
        }

        return false;
    }
}
