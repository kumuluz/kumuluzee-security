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

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.kumuluz.ee.configuration.utils.ConfigurationUtil;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Miha Jamsek
 * @since 1.3.0
 */
public class FirebaseConfig {
    
    private static final Logger LOG = Logger.getLogger(FirebaseConfig.class.getName());
    
    private static String roleClaimName;
    private static boolean onlyVerifiedEmail;
    
    public static void initialize() {
        try {
            
            FirebaseOptions options = new FirebaseOptions.Builder()
                .setCredentials(GoogleCredentials.getApplicationDefault())
                .build();
            
            FirebaseApp.initializeApp(options);
            
            ConfigurationUtil configUtil = ConfigurationUtil.getInstance();
            roleClaimName = configUtil.get("kumuluzee.security.firebase.role-claim").orElse("roles");
            onlyVerifiedEmail = configUtil.getBoolean("kumuluzee.security.firebase.only-verified-email").orElse(false);
            
        } catch (IOException e) {
            LOG.severe("Error reading google credentials for Firebase Authentication! Environment variable 'GOOGLE_APPLICATION_CREDENTIALS' must point to a valid google credentials JSON file.");
        }
    }
    
    public static String getRoleClaimName() {
        return roleClaimName;
    }
    
    public static boolean onlyVerifiedEmail() {
        return onlyVerifiedEmail;
    }
    
}
