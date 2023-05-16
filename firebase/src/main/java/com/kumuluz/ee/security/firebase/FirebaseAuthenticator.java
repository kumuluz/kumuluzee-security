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

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;
import java.util.Optional;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
public class FirebaseAuthenticator implements Authenticator {
    
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";
    private static final String AUTH_METHOD = "JWT";
    
    @Override
    public void setConfiguration(AuthConfiguration authConfiguration) {
        // No configuration needed
    }
    
    @Override
    public String getAuthMethod() {
        return AUTH_METHOD;
    }
    
    @Override
    public void prepareRequest(ServletRequest servletRequest) {
        // No preparing request needed
    }
    
    @Override
    public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean b) throws ServerAuthException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        
        // 1. check if token is present and validate it
        Optional<String> token = extractToken(request);
        if (token.isPresent()) {
            try {
                FirebaseToken parsedToken = FirebaseAuth.getInstance().verifyIdToken(token.get(), FirebaseConfig.checkRevoked());
                if (FirebaseConfig.onlyVerifiedEmail() && !parsedToken.isEmailVerified()) {
                    return Authentication.UNAUTHENTICATED;
                }
        
                FirebasePrincipal principal = new FirebasePrincipal(parsedToken);
                return new FirebaseAuthentication(this, token.get(), principal);
        
            } catch (Exception e) {
                return Authentication.UNAUTHENTICATED;
            }
        }
    
        // 2. If no token, check if session cookie is present and validate it
        if (FirebaseConfig.allowSessionCookie()) {
            Optional<String> cookie = extractCookie(request);
            if (cookie.isPresent()) {
                try {
                    FirebaseToken parsedToken = FirebaseAuth.getInstance().verifySessionCookie(cookie.get(), FirebaseConfig.checkSessionRevoked());
                    if (FirebaseConfig.onlyVerifiedEmail() && !parsedToken.isEmailVerified()) {
                        return Authentication.UNAUTHENTICATED;
                    }
                    FirebasePrincipal principal = new FirebasePrincipal(parsedToken);
                    return new FirebaseAuthentication(this, cookie.get(), principal);
                } catch (Exception e) {
                    return Authentication.UNAUTHENTICATED;
                }
            }
        }
        
        // 3. If neither token, nor cookie present
        return Authentication.UNAUTHENTICATED;
    }
    
    @Override
    public boolean secureResponse(ServletRequest servletRequest, ServletResponse servletResponse, boolean b, Authentication.User user) throws ServerAuthException {
        return true;
    }
    
    private Optional<String> extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return Optional.empty();
        }
        
        if (header.startsWith(BEARER_TOKEN_PREFIX)) {
            return Optional.of(header.substring(BEARER_TOKEN_PREFIX.length()));
        }
        
        return Optional.empty();
    }
    
    private Optional<String> extractCookie(HttpServletRequest request) {
        String cookieName = ConfigurationUtil.getInstance().get("kumuluzee.security.firebase.session.cookie.name").orElse("session");
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        return Optional.empty();
    }
}
