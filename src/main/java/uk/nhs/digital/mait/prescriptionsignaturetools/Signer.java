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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import javax.xml.crypto.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.warlock.util.xsltransform.TransformManager;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
/**
 *
 * @author DAMU2
 */
public class Signer 
    extends Thread
    implements URIDereferencer
{
    static final String FRAGMENTEXTRACTOR = "/Prescriptionv0r1.xslt";
    static final String SPACESTRIPPER = "/SignedInfowhitespacev0r1.xslt";    
    
    private static final int READBUFFER = 51200;
    
    private int operation = PrescriptionSignatureTools.UNDEFINED;
    private ArrayList<File> prescriptions = null;
    private File signedPrescriptionsDirectory = null;
    private boolean stopOnError = false;
    private JKSCryptoProvider crypto = null;
    private CryptoProviderFactory cryptoFactory = null;
    
    private String fragmentExtractorTransform = null;
    private String spaceStripperTransform = null;
    
    private String fragments = null;
    private PrescriptionSignatureTools tool = null;
    
    private HashMap<String,String> utfSubstitutions = null;
    
    public Signer(String outDir, int op, HashMap<String,String> utfs) 
            throws Exception
    {
        operation = op;
        utfSubstitutions = utfs;
        prescriptions = new ArrayList<>();
        if (op == PrescriptionSignatureTools.SIGN) {        
            signedPrescriptionsDirectory = new File(outDir);
            if (!signedPrescriptionsDirectory.exists()) {
                throw new Exception("No such directory: " + outDir);
            }
            if (!signedPrescriptionsDirectory.isDirectory()) {
                throw new Exception("No such directory: " + outDir);
            }
            if (!signedPrescriptionsDirectory.canWrite()) {
                throw new Exception("Output directory not writable: " + outDir);
            }
            if (!signedPrescriptionsDirectory.canExecute()) {
                throw new Exception("Output directory not writable: " + outDir);
            }
        }
        TransformManager t = TransformManager.getInstance();
        
        StringBuilder sb = new StringBuilder(FRAGMENTEXTRACTOR);
        sb.append(this.hashCode());
        fragmentExtractorTransform = sb.toString();
        sb = new StringBuilder(SPACESTRIPPER);
        sb.append(this.hashCode());
        spaceStripperTransform = sb.toString();
        t.addTransform(fragmentExtractorTransform, this.getClass().getResourceAsStream(FRAGMENTEXTRACTOR));
        t.addTransform(spaceStripperTransform, this.getClass().getResourceAsStream(SPACESTRIPPER));        
        
    }
    
    public void setTool(PrescriptionSignatureTools t) { tool = t; }
        
    public void setCryptoProvider(JKSCryptoProvider c) { crypto = c; }
    public void setCryptoProviderFactory(CryptoProviderFactory cpf) { cryptoFactory = cpf; }
    
    public void setStopOnError() { stopOnError = true; }
    
    public void setFiles(File[] f) { 
        prescriptions.addAll(Arrays.asList(f)); 
    }
    
    public void addFile(File f) { prescriptions.add(f); }
    
    @Override
    @SuppressWarnings("CallToPrintStackTrace")
    public void run() {
        
//        String fragments = null;
        for (File f : prescriptions) {
            try {
                fragments = null;
                String rx = readFile(f);
                switch(operation) {
                    case PrescriptionSignatureTools.SIGN:
                        sign(f.getName(),rx);
                        break;
                        
                    case PrescriptionSignatureTools.VERIFY:
                        verify(f.getName(), rx);
                        break;
                        
                    case PrescriptionSignatureTools.RRVERIFY:
                        verifyReleaseResponse(f.getName(), rx);
                        break;
                }                
            }
            catch (Exception e) {
                e.printStackTrace();
                if (stopOnError) {
                    if (tool != null) {
                        tool.signerEnd();
                    }
                    return;
                }
            }
        }
        if (tool != null) {
            tool.signerEnd();
        }
    }
    
    @SuppressWarnings({"ConvertToTryWithResources", "UnusedAssignment"})
    private String readFile(File f)
            throws Exception
    {
        // Modify this so it reads into a byte buffer first, strips off
        // any BOM and then uses that byte buffer to feed the Reader
        //
        
        FileInputStream fis = new FileInputStream(f);
        long l = f.length();
        byte[] buffer = new byte[(int)l];
        int pos = 0;
        @SuppressWarnings("UnusedAssignment")
        int read = -1;
        while ((read = fis.read(buffer, pos, (int)(l - pos))) != -1) {
            pos += read;
            if (pos == l)
                break;
        }
        fis.close();
        pos = 0;
        // Check for UTF-8 BOM ... can add any others if needed
        if ((buffer[0] == (byte)0xef) && (buffer[1] == (byte)0xbb) && (buffer[2] == (byte)0xbf)) {
            pos = 3;
        }
        StringBuilder sb = new StringBuilder();
        ByteArrayInputStream bis = new ByteArrayInputStream(buffer, pos, (int)(l - pos));
        InputStreamReader isr = new InputStreamReader(bis);
        char[] b = new char[READBUFFER];
        read = -1;
        while ((read = isr.read(b)) != -1) {
            sb.append(b, 0, read);
        }
        isr.close();
        if (operation == PrescriptionSignatureTools.SIGN) {
            if ((utfSubstitutions != null) && (!utfSubstitutions.isEmpty())) {
                doSubstitutions(sb);
            }
        }
        return sb.toString();
    }
    
    private StringBuilder doSubstitutions(StringBuilder sb)
            throws Exception
    {
        for (String s : utfSubstitutions.keySet()) {
            @SuppressWarnings("UnusedAssignment")
            int start = 0;
            while ((start = sb.indexOf(s)) != -1) {
                sb.replace(start, start + s.length(), utfSubstitutions.get(s));
            }
        }
        return sb;
    }
    
    @SuppressWarnings("ConvertToTryWithResources")
    private void sign(String fname, String xml)
            throws Exception
    {
        // Get the initial letter of the file name, and resolve a suitable
        // crypto provider.
        //
//        String t = fname.substring(0, 1);
        SigningOptions sopts = SigningOptions.resolveOptions(fname);
        CryptoProvider cp = cryptoFactory.getProvider(sopts.getProvider());
        if (cp == null) {
            if (sopts.doNotSign()) {
                try {
                    FileOutputStream outfile = new FileOutputStream(new File(signedPrescriptionsDirectory, fname));
                    OutputStreamWriter osw = new OutputStreamWriter(outfile, Charset.forName("UTF-8"));
                    osw.write(xml);
                    osw.flush();
                    return;
                }
                catch (IOException e) {
                    System.err.println("Exception writing unsigned prescription: " + e.toString());
                }
            } else {
                String msg = "Crypto provider for type " + sopts.getProvider() + " not set";
                System.err.println(msg);
                if (stopOnError) {
                    throw new Exception(msg);
                }
                return;
            }
        }
        // Apply the two xsl transforms to the XML, then
        // call crypto.sign() and write the result to the output
        // directory.        
        TransformManager tm = TransformManager.getInstance();
        @SuppressWarnings("UnusedAssignment")
        byte[] b = null;
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OutputStreamWriter osw = new OutputStreamWriter(out, Charset.forName("UTF-8"));
            osw.write(xml);
            osw.flush();
            b = out.toByteArray();
        }
        catch (IOException e) {
            System.err.println("Exception writing UTF-8 encoded prescription: " + e.toString());
            return;
        }
        fragments = tm.doTransform(fragmentExtractorTransform, new ByteArrayInputStream(b));
        
        // "Case G" broken hash... A validator will run the fragment extractor
        // itself... so we need to invalidate the signed hash by tweaking the 
        // content of the "fragments".
        //
        if (sopts.breakHash()) {
            // The FragmentsToBeHashed contains a time which starts with a year,
            // so assume the first character is a "2" and replace it with a "9".
            // Note: This is a temporary fix and will need updating in 9000AD.
            StringBuilder sb = new StringBuilder(fragments);
            int two = sb.indexOf("value=\"2");
            if (two == -1) {
                throw new Exception("Unexpected... could not find time element in fragments");
            }
            two += ("value=\"2".length() - 1);
            sb.replace(two, two, "9");
            fragments = sb.toString();
        }

//        String sfrag = tm.doTransform(SPACESTRIPPER, fragments);
        Element signature = cp.sign(fragments, this, sopts);

        // This "signature" element needs adopting into the document for
        // the prescription, and the original signatureText element replacing
        // with the adopted version here.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringComments(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(xml.toCharArray())));
        doc.adoptNode(signature);
        Element nullSig = (Element) doc.getElementsByTagName("signatureText").item(0);
        nullSig.appendChild(signature);
        nullSig.removeAttribute("nullFlavor");

        // Cases where we need to "break" the signature by post-processing.
        //
        if (sopts.breakDigest()) {
            // Break the "DigestValue" in "SignedInfo"
            Element digestValue = (Element) signature.getElementsByTagName("DigestValue").item(0);
            String dval = digestValue.getTextContent();
            dval = breakCryptographicString(dval);
            digestValue.setTextContent(dval);
        }

        if (sopts.breakSignature()) {
            // Break the "SignatureValue"
            Element signatureValue = (Element) signature.getElementsByTagName("SignatureValue").item(0);
            String sval = signatureValue.getTextContent();
            sval = breakCryptographicString(sval);
            signatureValue.setTextContent(sval);
        }

        if (sopts.breakCertificate()) {
            // Break the "X509Certificate"
            Element x509cert = (Element) signature.getElementsByTagName("X509Certificate").item(0);
            String cval = x509cert.getTextContent();
            cval = breakCryptographicString(cval);
            x509cert.setTextContent(cval);
        }
        
        // Serialise
        //
        FileOutputStream outfile = new FileOutputStream(new File(signedPrescriptionsDirectory, fname));
        OutputStreamWriter osw = new OutputStreamWriter(outfile, Charset.forName("UTF-8"));
        StreamResult sr = new StreamResult(osw);
        Transformer tx = TransformerFactory.newInstance().newTransformer();
        tx.transform(new DOMSource(doc), sr);
        osw.flush();
        osw.close();
    }        
        
    private String breakCryptographicString(String s) 
    {
        if (s == null) {
            return s;
        }
        if (s.length() == 0) {
            return "X";
        }
        char[] c = s.toCharArray();
        for (int i = 0; i < 5; i++) {
            if (i == c.length) {
                break;
            }
            c[i] = (c[i] != 'A') ? 'A' : 'B';
        }
        return new String(c);
    }
    
    @Override
    public Data dereference(URIReference r, XMLCryptoContext xcc) {
        OctetStreamData oct = new OctetStreamData(new ByteArrayInputStream(fragments.getBytes()));
        return oct;
    }
    
    private void verifyReleaseResponse(String fname, String xml)
            throws Exception
    {
        // TODO: Split the releae response into prescriptions, and call verify() on each.
    }   
    
    private void verify(String fname, String xml)
            throws Exception
    {
        @SuppressWarnings("UnusedAssignment")
        Document doc = null;
        @SuppressWarnings("UnusedAssignment")
        Element sig = null;
        
        TransformManager tm = TransformManager.getInstance();
        CryptoProvider cp = cryptoFactory.getProvider(CryptoProviderFactory.VERIFY);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringComments(true);
        ArrayList<VerificationTarget> targets = getVerificationTargets(fname, xml, tm, dbf);
        for (VerificationTarget t : targets) {
            StringBuilder sb = new StringBuilder("File: ");
            sb.append(t.getFileName());
            sb.append(" UUID: ");
            sb.append(t.getId());
            String reportingname = sb.toString();
            try {
//                doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(hl7prescription.toCharArray())));
                doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(t.getRx().toCharArray())));
                sig = (Element)doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
            }
            catch (IOException | ParserConfigurationException | SAXException e) {
                System.out.println(reportingname + "\tFAILED\tCannot read signature");
                return;
            }
            if (sig == null){ 
                System.out.println(reportingname + "\tFAILED\tCannot read signature");
                return;
            }
            fragments = t.getFragments();
            if (cp.verify(reportingname, sig, fragments, this)) {
                System.out.println(reportingname + "\tSUCCESS");
            }
        }
    }
    
    private ArrayList<VerificationTarget> getVerificationTargets(String f, String x, TransformManager t, DocumentBuilderFactory dbf) {
    
        ArrayList<VerificationTarget> targets = new ArrayList<>();
        // TODO: The "xml" may be a nominated release response with multiple prescriptions in it. And it
        // may be anything in a log file. Abstract the try/catch block into a method that returns an
        // ArrayList<VerificationTarget> containing the transformed "fragments" for each extracted prescription,
        // the file name and the prescription id. Then put the actual verification into a loop.

        if (x.contains("PORX_IN070101UK31")) {
            boolean ok = false;
            boolean beenhere = false;
            String xml = x;
            while (!ok) {
                try {
                    Document doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(xml.toCharArray())));
                    NodeList nl = doc.getElementsByTagNameNS("urn:hl7-org:v3", "ParentPrescription");
                    if (nl.getLength() == 0) {
                        System.out.println(f + "\tFAILED\tCannot read prescriptions from nominated release response");
                        return targets;
                    }
                    for (int i = 0; i < nl.getLength(); i++) {
                        StringWriter osw = new StringWriter();
                        StreamResult sr = new StreamResult(osw);
                        Transformer tx = TransformerFactory.newInstance().newTransformer();
                        tx.transform(new DOMSource((Element)nl.item(i)), sr);
                        osw.flush();
                        String frag = t.doTransform(fragmentExtractorTransform, osw.toString());
                        targets.add(new VerificationTarget(f, frag, osw.toString(), getRxID(frag)));                        
                    }
                    ok = true;
                }
                catch (Exception e) {
                    if (beenhere) {
                        System.out.println(f + "\tFAILED\tCannot read prescriptions from nominated release response");
                        return targets;
                    }
                    beenhere = true;
                    xml = unpackFromLog(f, x);
                    if (xml != null) {
                        xml = xml.trim();
                    } else {
                        xml = x.trim();
                    }
                }
            }
        } else {
            try {
                String frag = t.doTransform(fragmentExtractorTransform, x);
                targets.add(new VerificationTarget(f, frag, x, getRxID(frag)));
            }
            catch (Exception e) {
                String h = unpackFromLog(f, x);
                if (h != null) {
                    h = h.trim();
                } else {
                    // Try trimming

                   h = x.trim();
                } 
                try {
                    String frag = t.doTransform(fragmentExtractorTransform, h);
                    targets.add(new VerificationTarget(f, frag, x, getRxID(frag)));
                }
                catch (Exception e1) {
                    System.out.println(f + "\tFAILED\tCannot read prescription or fragment extract failed");
                }
                
            }
        }          
        return targets;
    }
    
    private String getRxID(String f) {
        String s = f.substring(f.indexOf("root=\"") + 6);
        s = s.substring(0, s.indexOf("\""));
        return s;
    }
    
    private String unpackFromLog(String fname, String l) 
    {
        // Find the 4th instance of \r\n\r\n 
        
        int hl7start = 0;
        int hl7end = 0;
        for (int i = 0; i < 4; i++) {
            hl7start = l.indexOf("\r\n\r\n", hl7start + 1);
            if (hl7start == -1) {
                System.out.println(fname + "\tFAILED\tBad file, can't find HL7 prescription start");
                return null;
            }
        }
        // Find the 3rd \r\n----
        for (int i = 0; i < 3; i++) {
            hl7end = l.indexOf("\r\n----", hl7end + 1);
            if (hl7end == -1) {
                System.out.println(fname + "\tFAILED\tBad file, can't find HL7 prescription end");
                return null;            
            }
        }
        
        return l.substring(hl7start, hl7end);
    }
}
