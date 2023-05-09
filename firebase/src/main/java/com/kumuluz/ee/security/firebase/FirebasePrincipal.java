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
package com.kumuluz.ee.security.firebase;

import com.google.firebase.auth.FirebaseToken;

import java.security.Principal;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
public class FirebasePrincipal implements Principal {
    
    private static final Logger LOG = Logger.getLogger(FirebasePrincipal.class.getName());
    
    private final FirebaseToken token;
    
    private final String uid;
    
    private final Set<String> roles;
    
    public FirebasePrincipal(FirebaseToken parsedToken) {
        this.uid = parsedToken.getUid();
        this.token = parsedToken;
        this.roles = getRoles(parsedToken);
    }
    
    @Override
    public String getName() {
        return this.uid;
    }
    
    public Set<String> getRoles() {
        return roles;
    }
    
    public String getUsername() {
        return token.getName();
    }
    
    public String getEmail() {
        return token.getEmail();
    }
    
    @Override
    public int hashCode() {
        return getName().hashCode();
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        } else if (!(obj instanceof FirebasePrincipal)) {
            return false;
        }
        return getName().equals(((FirebasePrincipal) obj).getName());
    }
    
    @Override
    public String toString() {
        return getName();
    }
    
    private Set<String> getRoles(FirebaseToken token) {
        final String roleClaimName = FirebaseConfig.getRoleClaimName();
        Map<String, Object> claims = token.getClaims();
        
        if (claims.containsKey(roleClaimName)) {
            Object roleClaim = claims.get(roleClaimName);
            
            if (roleClaim instanceof String) {
                return Collections.singleton((String) roleClaim);
            } else if (roleClaim instanceof Collection<?>) {
                try {
                    return ((Collection<?>) roleClaim).stream()
                        .map(String.class::cast)
                        .collect(Collectors.toSet());
                } catch (ClassCastException e) {
                    LOG.log(Level.SEVERE, "Role claim ''{0}'' is not an array of strings!", roleClaimName);
                    return Collections.emptySet();
                }
            } else {
                LOG.log(Level.SEVERE, "Role claim ''{0}'' is not an array of strings!", roleClaimName);
                return Collections.emptySet();
            }
        }
        
        return Collections.emptySet();
    }
}
