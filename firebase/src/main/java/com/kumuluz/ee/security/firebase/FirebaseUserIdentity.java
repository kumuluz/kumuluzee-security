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

import org.eclipse.jetty.server.UserIdentity;

import javax.security.auth.Subject;
import java.security.Principal;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
public class FirebaseUserIdentity implements UserIdentity {
    
    private final FirebasePrincipal principal;
    
    public FirebaseUserIdentity(final FirebasePrincipal principal) {
        this.principal = principal;
    }
    
    @Override
    public Subject getSubject() {
        final Subject subject = new Subject();
        subject.getPrincipals().add(principal);
        return subject;
    }
    
    @Override
    public Principal getUserPrincipal() {
        return principal;
    }
    
    @Override
    public boolean isUserInRole(String role, Scope scope) {
        return principal.getRoles().stream().anyMatch(userRole -> userRole.equals(role));
    }
    
    @Override
    public String toString() {
        return principal.getName();
    }
}
