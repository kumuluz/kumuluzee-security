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

import com.kumuluz.ee.security.firebase.FirebasePrincipal;
import com.kumuluz.ee.security.utils.SecurityProcessorUtil;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
@RequestScoped
public class FirebaseSecurityProcessorUtilImpl implements SecurityProcessorUtil {
    
    @Inject
    private HttpServletRequest httpServletRequest;
    
    @Inject
    private FirebaseSecurityConfigurationUtilImpl firebaseSecurityConfigurationUtil;
    
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
        
        FirebasePrincipal firebasePrincipal = (FirebasePrincipal) principal;
        final Set<String> roles = firebasePrincipal.getRoles();
        
        Map<String, String> roleMappings = firebaseSecurityConfigurationUtil.getRoleMappings();
        Stream<String> rolesStream;
        if (roleMappings != null && !roleMappings.isEmpty()) {
            rolesStream = roles
                .stream()
                .map(r -> roleMappings.getOrDefault(r, null))
                .filter(Objects::nonNull);
        } else {
            rolesStream = roles.stream();
        }
        
        boolean isAllowed = rolesStream.anyMatch(rolesAllowed::contains);
        if (!isAllowed)
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
    }
    
    @Override
    public void processPermitAll() {
        processAuthentication();
    }
}
