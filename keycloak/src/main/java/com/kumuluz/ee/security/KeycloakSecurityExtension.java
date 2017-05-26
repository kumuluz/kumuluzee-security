package com.kumuluz.ee.security;

import com.kumuluz.ee.common.Extension;
import com.kumuluz.ee.common.config.EeConfig;
import com.kumuluz.ee.common.dependencies.*;
import com.kumuluz.ee.common.wrapper.KumuluzServerWrapper;

import java.util.logging.Logger;

/**
 * KumuluzEE framework extension for Keycloak based security
 *
 * @author Benjamin Kastelic
 */
@EeExtensionDef(name = "keycloak", type = EeExtensionType.SECURITY)
@EeComponentDependencies({
        @EeComponentDependency(EeComponentType.SERVLET),
        @EeComponentDependency(EeComponentType.CDI)
})
public class KeycloakSecurityExtension implements Extension {

    private static final Logger log = Logger.getLogger(KeycloakSecurityExtension.class.getName());

    @Override
    public void init(KumuluzServerWrapper kumuluzServerWrapper, EeConfig eeConfig) {
        log.info("Initialising security implemented by Keycloak.");
    }

    @Override
    public void load() {
        log.info("Initialised security implemented by Keycloak.");
    }
}
