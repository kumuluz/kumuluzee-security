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
package com.kumuluz.ee.security.models;

import java.util.List;

/**
 * @author Benjamin Kastelic
 */
public class SecurityConstraint {

    private String method;
    private String path;
    private List<String> roles;
    private boolean anyRole;

    public SecurityConstraint(String method, String path, List<String> roles) {
        this.method = method;
        this.path = path;
        this.roles = roles;
    }

    public SecurityConstraint(String method, String path) {
        this.method = method;
        this.path = path;
        this.anyRole = true;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public boolean getAnyRole() {
        return anyRole;
    }

    public void setAnyRole(boolean anyRole) {
        this.anyRole = anyRole;
    }
}
