package com.kumuluz.ee.security.utils;

import java.security.Principal;
import java.util.List;

/**
 * Created by Benjamin on 29. maj 2017.
 */
public interface SecurityProcessorUtil {

    void processDenyAll();

    void processRolesAllowed(List<String> rolesAllowed);

    void processPermitAll();
}
