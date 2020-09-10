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
class VerificationTarget {
    private String filename = null;
    private String hl7rx = null;
    private String fragments = null;
    private String rxid = null;
    
    VerificationTarget(String f, String x, String h, String id) {
        filename = f;
        fragments = x;
        hl7rx = h;
        rxid = id;
    }
    
    String getFileName() { return filename; }
    String getFragments() { return fragments; }
    String getId() { return rxid; }
    String getRx() { return hl7rx; }
}
