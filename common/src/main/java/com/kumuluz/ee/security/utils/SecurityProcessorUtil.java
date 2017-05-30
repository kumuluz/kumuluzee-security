package com.kumuluz.ee.security.utils;

import java.util.List;

/**
 * @author Benjamin Kastelic
 */
public interface SecurityProcessorUtil {

    void processDenyAll();

    void processRolesAllowed(List<String> rolesAllowed);

    void processPermitAll();
}
