package com.kumuluz.ee.security.interceptors;

import com.kumuluz.ee.security.annotations.RolesAllowed;
import com.kumuluz.ee.security.utils.SecurityAnnotationHelper;
import com.kumuluz.ee.security.utils.SecurityProcessorUtil;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.ws.rs.Priorities;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Benjamin on 29. maj 2017.
 */
@RolesAllowed
@Interceptor
@Priority(Priorities.AUTHORIZATION + 2)
public class RolesAllowedInterceptor {

    @Inject
    private SecurityProcessorUtil securityProcessorUtil;

    @AroundInvoke
    public Object checkPermission(InvocationContext context) throws Exception {
        if (SecurityAnnotationHelper.isSecurityProcessed(context)) {
            return context.proceed();
        }

        if (SecurityAnnotationHelper.hasDenyAllOverride(context.getMethod())) {
            securityProcessorUtil.processDenyAll();
        } else if (SecurityAnnotationHelper.hasPermitAllOverride(context.getMethod())) {
            securityProcessorUtil.processPermitAll();
        } else {
            securityProcessorUtil.processRolesAllowed(SecurityAnnotationHelper.getRolesAllowed(context));
        }

        SecurityAnnotationHelper.setSecurityProcessed(context);

        return context.proceed();
    }
}
