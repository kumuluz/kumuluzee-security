package com.kumuluz.ee.security;

import com.kumuluz.ee.security.models.SecurityConstraint;
import com.kumuluz.ee.security.utils.SecurityConfigurationUtil;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.webapp.WebAppContext;
import org.keycloak.adapters.jetty.KeycloakJettyAuthenticator;

import javax.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Benjamin Kastelic
 */
@ApplicationScoped
public class KeycloakSecurityConfigurationUtilImpl implements SecurityConfigurationUtil {

    @Override
    public void configureSecurity(String keycloakConfig, Object context, List<String> declaredRoles, List<SecurityConstraint> constraints) {
        WebAppContext.Context webAppContext = null;
        WebAppContext webAppContextHandler = null;

        if (context instanceof WebAppContext.Context) {
            webAppContext = (WebAppContext.Context) context;
        }

        if (webAppContext != null && webAppContext.getContextHandler() instanceof WebAppContext) {
            webAppContextHandler = (WebAppContext) webAppContext.getContextHandler();
        }

        if (webAppContextHandler != null) {
            ConstraintSecurityHandler constraintSecurityHandler = new ConstraintSecurityHandler();
            constraintSecurityHandler.setAuthenticator(new KeycloakJettyAuthenticator());

            Set<String> roles = new HashSet<>(declaredRoles);
            constraintSecurityHandler.setRoles(roles);
            List<ConstraintMapping> constraintMappings = toConstraintMappings(constraints);
            constraintSecurityHandler.setConstraintMappings(constraintMappings);

            webAppContextHandler.setSecurityHandler(constraintSecurityHandler);
        }

        if (webAppContext != null) {
            webAppContext.setInitParameter("org.keycloak.json.adapterConfig", keycloakConfig);
        }
    }

    private List<ConstraintMapping> toConstraintMappings(List<SecurityConstraint> constraints) {
        List<ConstraintMapping> constraintMappings = new ArrayList<>();
        constraints.forEach(constraint -> constraintMappings.add(toConstraintMapping(constraint)));
        return constraintMappings;
    }

    private ConstraintMapping toConstraintMapping(SecurityConstraint constraint) {
        Constraint constraint1 = new Constraint();
        if (constraint.getAnyRole()) {
            constraint1.setRoles(new String[]{"*"});
        } else {
            constraint1.setRoles(constraint.getRoles().toArray(new String[constraint.getRoles().size()]));
        }
        constraint1.setAuthenticate(true);

        ConstraintMapping constraintMapping = new ConstraintMapping();
        constraintMapping.setMethod(constraint.getMethod());
        constraintMapping.setPathSpec(constraint.getPath());
        constraintMapping.setConstraint(constraint1);

        return constraintMapping;
    }
}
