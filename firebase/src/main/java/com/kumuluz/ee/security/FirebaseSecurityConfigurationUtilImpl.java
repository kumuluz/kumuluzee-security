/*
 *  Copyright (c) 2014-2020 Kumuluz and/or its affiliates
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
package com.kumuluz.ee.security;

import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.kumuluz.ee.security.firebase.FirebaseAuthenticator;
import com.kumuluz.ee.security.models.SecurityConstraint;
import com.kumuluz.ee.security.utils.SecurityConfigurationUtil;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.enterprise.context.ApplicationScoped;
import java.util.*;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
@ApplicationScoped
public class FirebaseSecurityConfigurationUtilImpl implements SecurityConfigurationUtil {
    
    private Map<String, String> roleMappings;
    
    @Override
    public Map<String, String> getRoleMappings() {
        return roleMappings;
    }
    
    @Override
    public void setRoleMappings(Map<String, String> roleMappings) {
        this.roleMappings = roleMappings;
    }
    
    @Override
    @SuppressWarnings("rawtypes")
    public void configureSecurity(Class targetClass, Object context, List<String> declaredRoles, List<SecurityConstraint> constraints, Map<String, String> roleMappings) {
        WebAppContext.Context webAppContext = null;
        WebAppContext webAppContextHandler = null;
    
        if (context instanceof WebAppContext.Context) {
            webAppContext = (WebAppContext.Context) context;
        }
    
        if (webAppContext != null && webAppContext.getContextHandler() instanceof WebAppContext) {
            webAppContextHandler = (WebAppContext) webAppContext.getContextHandler();
        }
    
        final ConfigurationUtil configurationUtil = ConfigurationUtil.getInstance();
    
        if (webAppContextHandler != null) {
            ConstraintSecurityHandler constraintSecurityHandler = new ConstraintSecurityHandler();
            constraintSecurityHandler.setAuthenticator(new FirebaseAuthenticator());
        
            // Allows to disable security in jetty servlet
            boolean jettyAuthDisabled = configurationUtil.getBoolean("kumuluzee.security.disable-jetty-auth").orElse(false);
            if (!jettyAuthDisabled) {
                Set<String> roles = new HashSet<>(declaredRoles);
                constraintSecurityHandler.setRoles(roles);
                List<ConstraintMapping> constraintMappings = toConstraintMappings(constraints);
                constraintSecurityHandler.setConstraintMappings(constraintMappings);
            }
        
            webAppContextHandler.setSecurityHandler(constraintSecurityHandler);
        }
    
        this.roleMappings = roleMappings;
    }
    
    private List<ConstraintMapping> toConstraintMappings(List<SecurityConstraint> constraints) {
        List<ConstraintMapping> constraintMappings = new ArrayList<>();
        constraints.forEach(constraint -> constraintMappings.add(toConstraintMapping(constraint)));
        return constraintMappings;
    }
    
    private ConstraintMapping toConstraintMapping(SecurityConstraint securityConstraint) {
        Constraint constraint = new Constraint();
        if (securityConstraint.getAnyRole()) {
            constraint.setRoles(new String[]{"*"});
        } else {
            constraint.setRoles(securityConstraint.getRoles().toArray(new String[securityConstraint.getRoles().size()]));
        }
        constraint.setAuthenticate(true);
        
        ConstraintMapping constraintMapping = new ConstraintMapping();
        constraintMapping.setMethod(securityConstraint.getMethod());
        constraintMapping.setPathSpec(securityConstraint.getPath());
        constraintMapping.setConstraint(constraint);
        
        return constraintMapping;
    }
}
