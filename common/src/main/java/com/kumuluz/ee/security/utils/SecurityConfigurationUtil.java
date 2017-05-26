package com.kumuluz.ee.security.utils;

import com.kumuluz.ee.security.models.SecurityConstraint;

import java.util.List;

/**
 * @author Benjamin Kastelic
 */
public interface SecurityConfigurationUtil {

    void configureSecurity(String config, Object context, List<String> declaredRoles, List<SecurityConstraint> constraints);
}
