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
        if (securityAnnotation == null)
            return context.proceed();

        if (securityAnnotation instanceof DenyAll) {
            securityProcessorUtil.processDenyAll();
        } else if (securityAnnotation instanceof RolesAllowed) {
            securityProcessorUtil.processRolesAllowed(SecurityAnnotationHelper.getRolesAllowed(context.getMethod()));
        } else if (securityAnnotation instanceof PermitAll) {
            securityProcessorUtil.processPermitAll();
        }

        return context.proceed();
    }
}
