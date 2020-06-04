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

import javax.xml.crypto.URIDereferencer;
import org.w3c.dom.Element;

/**
 *
 * @author Damian Murphy
 */
public interface CryptoProvider {

    public Element sign(String rx, URIDereferencer urid, SigningOptions sopts)
            throws Exception;

    public boolean verify(String fname, Element signatureNode, String rx, URIDereferencer urid)
            throws Exception;
    
}
