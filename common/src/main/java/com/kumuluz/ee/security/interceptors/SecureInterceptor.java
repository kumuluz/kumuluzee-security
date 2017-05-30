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
package com.kumuluz.ee.security.interceptors;

import com.kumuluz.ee.security.annotations.Secure;
import com.kumuluz.ee.security.utils.SecurityAnnotationHelper;
import com.kumuluz.ee.security.utils.SecurityProcessorUtil;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.ws.rs.Priorities;

/**
 * An interceptor that handles CDI security.
 *
 * @author Benjamin Kastelic
 */
@Secure
@Interceptor
@Priority(Priorities.AUTHORIZATION)
public class SecureInterceptor {

    @Inject
    private SecurityProcessorUtil securityProcessorUtil;

    @AroundInvoke
    public Object checkPermission(InvocationContext context) throws Exception {
        Object securityAnnotation = SecurityAnnotationHelper.getSecurityAnnotation(context.getMethod());
        if (securityAnnotation == null) {
            securityProcessorUtil.processAuthentication();
        } else {
            if (securityAnnotation instanceof DenyAll) {
                securityProcessorUtil.processDenyAll();
            } else if (securityAnnotation instanceof RolesAllowed) {
                securityProcessorUtil.processRolesAllowed(SecurityAnnotationHelper.getRolesAllowed(context.getMethod()));
            } else if (securityAnnotation instanceof PermitAll) {
                securityProcessorUtil.processPermitAll();
            }
        }

        return context.proceed();
    }
}
