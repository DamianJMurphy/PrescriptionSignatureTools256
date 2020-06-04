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

/**
 *
 * @author Damian Murphy
 */
public class SigningOptions {

    private boolean hash = false;
    private boolean digest = false;
    private boolean signature = false;
    private boolean cert = false;
    private String algorithm = "SHA256";
    private String provider = CryptoProviderFactory.GOOD;
    
    static SigningOptions resolveOptions(String fname) {
        
        SigningOptions s = new SigningOptions();
        if (fname != null){
            char[] cs = fname.toCharArray();
            for (char c : cs) {
                if (c == 'G')
                    s.hash = true;
                if (c == 'U')
                    s.algorithm = null;
                if (c == 'S')
                    s.algorithm = "SHA1";
                if (c == 'Z')
                    s.algorithm = "SHA256";
                if (c == 'X')
                    s.cert = true;
                if (c == 'I')
                    s.signature = true;
                if (c == 'H')
                    s.digest = true;
                if (c == 'C')
                    s.provider = CryptoProviderFactory.BAD_CA;
                if (c == 'E')
                    s.provider = CryptoProviderFactory.EXPIRED;
                if (c == '-')
                    break;
            }
        }
        return s;
    }

    String getHashAlgorithm() {
        return algorithm;
    }
    
    boolean breakHash() {
        return hash;
    }

    String getProvider() {
        return provider;
    }

    boolean doNotSign() {
        return (algorithm == null);
    }

    boolean breakDigest() {
        return digest;
    }

    boolean breakSignature() {
        return signature;
    }

    boolean breakCertificate() {
        return cert;
    }
    
}
