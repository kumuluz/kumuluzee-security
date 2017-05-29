package com.kumuluz.ee.security.interceptors;

import com.kumuluz.ee.security.annotations.PermitAll;
import com.kumuluz.ee.security.utils.SecurityAnnotationHelper;
import com.kumuluz.ee.security.utils.SecurityProcessorUtil;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.ws.rs.Priorities;

/**
 * Created by Benjamin on 29. maj 2017.
 */
@PermitAll
@Interceptor
@Priority(Priorities.AUTHORIZATION + 3)
public class PermitAllInterceptor {

    @Inject
    private SecurityProcessorUtil securityProcessorUtil;

    @AroundInvoke
    public Object checkPermission(InvocationContext context) throws Exception {
        if (SecurityAnnotationHelper.isSecurityProcessed(context)) {
            return context.proceed();
        }

        if (SecurityAnnotationHelper.hasDenyAllOverride(context.getMethod())) {
            securityProcessorUtil.processDenyAll();
        } else if (SecurityAnnotationHelper.hasRolesAllowedOverride(context.getMethod())) {
            securityProcessorUtil.processRolesAllowed(SecurityAnnotationHelper.getRolesAllowed(context));
        } else {
            securityProcessorUtil.processPermitAll();
        }

        SecurityAnnotationHelper.setSecurityProcessed(context);

        return context.proceed();
    }
}
