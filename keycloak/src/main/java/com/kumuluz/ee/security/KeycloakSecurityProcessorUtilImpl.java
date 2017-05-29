package com.kumuluz.ee.security;

import com.kumuluz.ee.security.utils.SecurityProcessorUtil;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import java.security.Principal;
import java.util.List;

/**
 * Created by Benjamin on 29. maj 2017.
 */
@RequestScoped
public class KeycloakSecurityProcessorUtilImpl implements SecurityProcessorUtil {

    @Inject
    private HttpServletRequest httpServletRequest;

    @Override
    public void processDenyAll() {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(401).build());

        throw new ForbiddenException(Response.status(403).build());
    }

    @Override
    public void processRolesAllowed(List<String> rolesAllowed) {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(401).build());

        KeycloakPrincipal<?> keycloakPrincipal = (KeycloakPrincipal<?>) principal;
        KeycloakSecurityContext keycloakSecurityContext = keycloakPrincipal.getKeycloakSecurityContext();
        AccessToken accessToken = keycloakSecurityContext.getToken();
        AccessToken.Access access = accessToken.getRealmAccess();

        boolean isAllowed = rolesAllowed.stream().anyMatch(access::isUserInRole);
        if (!isAllowed)
            throw new ForbiddenException(Response.status(403).build());
    }

    @Override
    public void processPermitAll() {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(401).build());
    }
}
