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

import com.kumuluz.ee.common.Extension;
import com.kumuluz.ee.common.config.EeConfig;
import com.kumuluz.ee.common.dependencies.*;
import com.kumuluz.ee.common.wrapper.KumuluzServerWrapper;
import com.kumuluz.ee.security.firebase.FirebaseConfig;

import java.util.logging.Logger;

/**
 * KumuluzEE framework extension for Firebase based security.
 *
 * @author Miha Jamsek
 * @since 1.3.0
 */
@EeExtensionDef(name = "firebase", group = EeExtensionGroup.SECURITY)
@EeComponentDependencies({
    @EeComponentDependency(EeComponentType.SERVLET),
    @EeComponentDependency(EeComponentType.CDI)
})
public class FirebaseSecurityExtension implements Extension {
    
    private static final Logger LOG = Logger.getLogger(FirebaseSecurityExtension.class.getName());
    
    @Override
    public void init(KumuluzServerWrapper kumuluzServerWrapper, EeConfig eeConfig) {
        LOG.info("Initializing security implemented by Firebase.");
        FirebaseConfig.initialize();
    }
    
    @Override
    public void load() {
        LOG.info("Initialized security implemented by Firebase.");
    }
}
