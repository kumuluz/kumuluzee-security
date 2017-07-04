/*
 *  Copyright (c) 2014-2017 Kumuluz and/or its affiliates
 *  and other contributors as indicated by the @author tags and
 *  the contributor list.
 *
 *  Licensed under the MIT License (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://opensource.org/licenses/MIT
 *
 *  The software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or
 *  implied, including but not limited to the warranties of merchantability,
 *  fitness for a particular purpose and noninfringement. in no event shall the
 *  authors or copyright holders be liable for any claim, damages or other
 *  liability, whether in an action of contract, tort or otherwise, arising from,
 *  out of or in connection with the software or the use or other dealings in the
 *  software. See the License for the specific language governing permissions and
 *  limitations under the License.
 */
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

    public static Object getSecurityAnnotation(Method method) {
        if (method.getAnnotation(DenyAll.class) != null) // method level @DenyAll annotation
            return method.getAnnotation(DenyAll.class);
        if (method.getAnnotation(RolesAllowed.class) != null) // method level @RolesAllowed annotation
            return method.getAnnotation(RolesAllowed.class);
        if (method.getAnnotation(PermitAll.class) != null) // method level @PermitAll annotation
            return method.getAnnotation(PermitAll.class);
        if (method.getDeclaringClass().getAnnotation(DenyAll.class) != null) // class level @DenyAll annotation
            return method.getDeclaringClass().getAnnotation(DenyAll.class);
        if (method.getDeclaringClass().getAnnotation(RolesAllowed.class) != null) // class level @RolesAllowed annotation
            return method.getDeclaringClass().getAnnotation(RolesAllowed.class);
        if (method.getDeclaringClass().getAnnotation(PermitAll.class) != null) // class level @PermitAll annotation
            return method.getDeclaringClass().getAnnotation(PermitAll.class);

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
