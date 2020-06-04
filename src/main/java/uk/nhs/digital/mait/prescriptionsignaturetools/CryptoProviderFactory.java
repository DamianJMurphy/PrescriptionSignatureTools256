/*
 Copyright 2020  NHS Digital <damian.murphy@nhs.net>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
package uk.nhs.digital.mait.prescriptionsignaturetools;
import java.util.HashMap;
import java.util.Properties;
/**
 *
 * @author DAMU2
 */
public class CryptoProviderFactory {
    
    public static final String GOOD_KEYSTORE = "uk.nhs.digital.mait.prescriptionsignature.keystore";
    public static final String GOOD_USERID = "uk.nhs.digital.mait.prescriptionsignature.userid"; 
    public static final String GOOD_PASSWORD = "uk.nhs.digital.mait.prescriptionsignature.password";

    public static final String BADCA_KEYSTORE = "uk.nhs.digital.mait.prescriptionsignature.wrongca.keystore";
    public static final String BADCA_USERID = "uk.nhs.digital.mait.prescriptionsignature.wrongca.userid"; 
    public static final String BADCA_PASSWORD = "uk.nhs.digital.mait.prescriptionsignature.wrongca.password";

    public static final String EXPIRED_KEYSTORE = "uk.nhs.digital.mait.prescriptionsignature.expired.keystore";
    public static final String EXPIRED_USERID = "uk.nhs.digital.mait.prescriptionsignature.expired.userid"; 
    public static final String EXPIRED_PASSWORD = "uk.nhs.digital.mait.prescriptionsignature.expired.password";
   
    public static final String VERIFY = "V";
    
    public static final String EXPIRED = "E";
    public static final String BAD_CA = "C";
    public static final String BADHASH = "G";
    public static final String BADDIGEST = "H";
    public static final String BADSIGVALUE = "I";
    public static final String BADCERT = "X";
    public static final String GOOD = "S";
    public static final String NO = "U";
    
    private final HashMap<String,CryptoProvider> providers = new HashMap<>();
    
    @SuppressWarnings("CallToPrintStackTrace")
    public CryptoProviderFactory(Properties prop, boolean stop, boolean verify)
            throws Exception
    {
        if (verify) {
            providers.put(VERIFY, new JKSCryptoProvider());
        } else {
            @SuppressWarnings("UnusedAssignment")
            String ks = null;
            @SuppressWarnings("UnusedAssignment")
            String u = null;
            @SuppressWarnings("UnusedAssignment")
            String p = null;
            @SuppressWarnings("UnusedAssignment")
            CryptoProvider cp = null;

            // Good
            ks = prop.getProperty(GOOD_KEYSTORE);
            u = prop.getProperty(GOOD_USERID);
            p = prop.getProperty(GOOD_PASSWORD);
            if (ks.endsWith(".jks")) {
                cp = new JKSCryptoProvider(ks, p, u);
            } else {            
                cp = new PKCS12CryptoProvider(ks, p, u);
            }
            providers.put(GOOD, cp);

            // Also for "bad scenarios" based on an otherwise good signature
            //
            providers.put(BADHASH, cp);
            providers.put(BADDIGEST, cp);
            providers.put(BADSIGVALUE, cp);
            providers.put(BADCERT, cp);

            // Bad
            try {
                ks = prop.getProperty(BADCA_KEYSTORE);
                if (!ks.contentEquals("NOT_SET")) {
                    u = prop.getProperty(BADCA_USERID);
                    p = prop.getProperty(BADCA_PASSWORD);
                    if (ks.endsWith(".jks")) {
                        cp = new JKSCryptoProvider(ks, p, u);
                    } else {            
                        cp = new PKCS12CryptoProvider(ks, p, u);
                    }
                    providers.put(BAD_CA, cp);
                }
            }
            catch (Exception e) {
                if (stop) {
                    throw e;
                }
                e.printStackTrace();
            }
            // Expired
            try {
                ks = prop.getProperty(EXPIRED_KEYSTORE);
                if (!ks.contentEquals("NOT_SET")) {
                    ks = prop.getProperty(EXPIRED_KEYSTORE);
                    u = prop.getProperty(EXPIRED_USERID);
                    p = prop.getProperty(EXPIRED_PASSWORD);
                    if (ks.endsWith(".jks")) {
                        cp = new JKSCryptoProvider(ks, p, u);
                    } else {            
                        cp = new PKCS12CryptoProvider(ks, p, u);
                    }
                    providers.put(EXPIRED, cp);        
                }
            }
            catch (Exception e) {
                if (stop) {
                    throw e;
                }
                e.printStackTrace();            
            }
        }
    }
    
    public void addCryptoProvider(CryptoProvider c, String n) {
        providers.put(n, c);
    }
    
    public CryptoProvider getProvider(String s) { 
        if (s.contentEquals(GOOD)) {
            return providers.get(GOOD); 
        }
        if (s.contentEquals(NO)) {
            return null;
        }
        return providers.get(s);
    }
}
