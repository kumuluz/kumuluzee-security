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
 * @author Benjamin Kastelic
 */
@RequestScoped
public class KeycloakSecurityProcessorUtilImpl implements SecurityProcessorUtil {

    @Inject
    private HttpServletRequest httpServletRequest;

    @Override
    public void processAuthentication() {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
    }

    @Override
    public void processDenyAll() {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());

        throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
    }

    @Override
    public void processRolesAllowed(List<String> rolesAllowed) {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());

        KeycloakPrincipal<?> keycloakPrincipal = (KeycloakPrincipal<?>) principal;
        KeycloakSecurityContext keycloakSecurityContext = keycloakPrincipal.getKeycloakSecurityContext();
        AccessToken accessToken = keycloakSecurityContext.getToken();
        AccessToken.Access access = accessToken.getRealmAccess();

        boolean isAllowed = rolesAllowed.stream().anyMatch(access::isUserInRole);
        if (!isAllowed)
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
    }

    @Override
    public void processPermitAll() {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null)
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
    }
}
