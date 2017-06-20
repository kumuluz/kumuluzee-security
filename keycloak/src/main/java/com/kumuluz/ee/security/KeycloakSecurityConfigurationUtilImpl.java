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
package com.kumuluz.ee.security;

import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.kumuluz.ee.security.annotations.Keycloak;
import com.kumuluz.ee.security.models.SecurityConstraint;
import com.kumuluz.ee.security.utils.SecurityConfigurationUtil;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.webapp.WebAppContext;
import org.json.JSONException;
import org.json.JSONObject;
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
    public void configureSecurity(Class targetClass, Object context, List<String> declaredRoles, List<SecurityConstraint> constraints) {
        String keycloakConfig = getKeycloakConfig(targetClass);

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

    private String getKeycloakConfig(Class targetClass) {
        ConfigurationUtil configurationUtil = ConfigurationUtil.getInstance();

        Keycloak keycloakAnnotation = (Keycloak) targetClass.getAnnotation(Keycloak.class);

        String jsonString;
        JSONObject json;
        String authServerUrl;
        String sslRequired;

        jsonString = configurationUtil.get("kumuluzee.security.keycloak.json").orElse("{}");
        json = toJSONObject(jsonString);

        if (jsonString.isEmpty() && keycloakAnnotation != null) {
            jsonString = keycloakAnnotation.json();
            json = toJSONObject(jsonString);

            authServerUrl = keycloakAnnotation.authServerUrl();
            sslRequired = keycloakAnnotation.sslRequired();

            if (!authServerUrl.isEmpty()) {
                json.put("auth-server-url", authServerUrl);
            }

            if (!sslRequired.isEmpty()) {
                json.put("ssl-required", sslRequired);
            }
        }

        return json.toString();
    }

    private JSONObject toJSONObject(String jsonString) {
        JSONObject json;
        try {
            json = new JSONObject(jsonString);
        } catch (JSONException e) {
            json = new JSONObject();
        }
        return json;
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
