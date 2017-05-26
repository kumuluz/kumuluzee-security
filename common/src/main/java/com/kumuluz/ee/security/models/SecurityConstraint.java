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
