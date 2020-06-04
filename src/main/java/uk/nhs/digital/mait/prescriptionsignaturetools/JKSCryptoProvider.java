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
import java.io.CharArrayReader;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Date;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.warlock.util.dsig.SimpleKeySelector;
import org.xml.sax.InputSource;
/**
 *
 * @author DAMU2
 * 
 */
public class JKSCryptoProvider 
        implements CryptoProvider
{
    
    private String keystorefile = null;
    private static Signature signature = null;
    private KeyStore keystore = null;
    private PrivateKey privateKey = null;
    private String userId = null;
    @SuppressWarnings("FieldMayBeFinal")
//    private Key  key = null;
    private X509Certificate certificate = null;
    
    public JKSCryptoProvider() {
        
    }
    
    @SuppressWarnings("ConvertToTryWithResources")
    public JKSCryptoProvider(String c, String p, String a)
            throws Exception
    {
        if (c == null) {
            throw new Exception("No keystore file");
        }
        if (a == null) {
            throw new Exception("No user id");
        }
        keystorefile = c;
        char[] pw = null;
        if (p != null) {
            pw = p.toCharArray();
        }
        userId = a;
        FileInputStream fis = new FileInputStream(keystorefile);
        keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, pw);
        fis.close();
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(userId, new KeyStore.PasswordProtection(pw));
        if (entry == null) {
            System.out.println("No private key found for user id " + userId);
            System.out.println("Try one of the following: ");
            Enumeration<String> alist = keystore.aliases();
            while (alist.hasMoreElements()) {
                System.out.println(alist.nextElement());
            }
            System.exit(1);
        }
        privateKey = entry.getPrivateKey();
        certificate = (X509Certificate)keystore.getCertificate(userId);        
    }
    
    @Override
    public Element sign(String rx, URIDereferencer urid, SigningOptions sopts)
            throws Exception
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringComments(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(rx.toCharArray())));
        Node n = doc.getElementsByTagName("FragmentsToBeHashed").item(0);
        XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
        Transform t = xsf.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#" , (TransformParameterSpec)null);
        @SuppressWarnings("UnusedAssignment")
        Reference ref = null;
        @SuppressWarnings("UnusedAssignment")
        SignedInfo si = null;
        CanonicalizationMethod cm = xsf.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null);
        if (sopts.getHashAlgorithm().contentEquals("SHA1")) {
            ref = xsf.newReference(null, xsf.newDigestMethod(DigestMethod.SHA1, null), Collections.singletonList(t), null, null);
            si = xsf.newSignedInfo(cm, xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
        } else {
            ref = xsf.newReference(null, xsf.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(t), null, null);
            si = xsf.newSignedInfo(cm, xsf.newSignatureMethod(SignatureMethod.RSA_SHA256, null), Collections.singletonList(ref));            
        }
        KeyInfoFactory kif = xsf.getKeyInfoFactory();
        ArrayList<Object> x509content = new ArrayList<>();
//        x509content.add(certificate.getSubjectX500Principal().getName());
        x509content.add(certificate);
        X509Data xd = kif.newX509Data(x509content);
        
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
        DOMSignContext dsc = new DOMSignContext(privateKey, n);
        dsc.setURIDereferencer(urid);
        XMLSignature xs = xsf.newXMLSignature(si, ki);
        
        xs.sign(dsc);
        
        // Build a "Signature" element by extracting from "n"
        Element signatureElement = (Element)doc.getElementsByTagName("Signature").item(0);
        return signatureElement;
    }
    
    @Override
    public boolean verify(String fname, Element signatureNode, String rx, URIDereferencer urid)
            throws Exception
    {
        // 1. Get the certificate
        // 2. Add it to a SimpleKeySelector
        // 3. Make a DOMStructure from the signature
        // 4. Make a DOMValidateContext from the key selector and a Node made from rx
        // 5. Unmarshal the signature
        // 6. Validate
        NodeList smList = signatureNode.getElementsByTagName("SignatureMethod");
        if (smList.getLength() == 0) {
            System.out.println(fname + "\tFAILED\tUnable to find SignatureMethod");
            return false;
        } else {
            Node sm = smList.item(0);
            System.out.println("Note: " + fname + "\tSignatureMethod " + ((Element)sm).getAttribute("Algorithm"));
        }
        NodeList dmList = signatureNode.getElementsByTagName("DigestMethod");
        if (dmList.getLength() == 0) {
            System.out.println(fname + "\tFAILED\tUnable to find DigestMethod");
            return false;
        } else {
            Node dm = dmList.item(0);
            System.out.println("Note: " + fname + "\tDigestMethod " + ((Element)dm).getAttribute("Algorithm"));
        }
        Node crt = signatureNode.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate").item(0);
        NodeList crtChildren = crt.getChildNodes();
        String encodedKey = null;
        for (int i = 0; i < crtChildren.getLength(); i++) {
            Node kn = crtChildren.item(i);
            if (kn.getNodeType() == Node.TEXT_NODE) {
                encodedKey = kn.getNodeValue();
                break;
            }
        }
        if (encodedKey == null) {
            System.out.println(fname + "\tFAILED\tUnable to resolve encoded certificate in <X509Certificate>");
            return false;
        }
        StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        sb.append(encodedKey);
        if (encodedKey.charAt(encodedKey.length() - 1) != '\n') {
            sb.append("\n");
        }
        sb.append("-----END CERTIFICATE-----");
        String skey = sb.toString();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        @SuppressWarnings("UnusedAssignment")
        X509Certificate x = null;
        try {
            x = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(sb.toString().getBytes()));
        }
        catch (CertificateException e) {
            System.out.println(fname + "\tFAILED\tUnable to parse certificate");
            return false;
        }
                
        String cIssuer = x.getIssuerX500Principal().getName();
        String cSubject = x.getSubjectX500Principal().getName();
        String cStart = x.getNotBefore().toString();
        String cEnd = x.getNotAfter().toString();
        StringBuilder certDetails = new StringBuilder(fname);
        certDetails.append("\tCertificate details");
        Date now = new Date();
        if (x.getNotBefore().compareTo(now) > 0) 
            certDetails.append("\tWARNING: NOT YET VALID ");
        if (x.getNotAfter().compareTo(now) < 0)
            certDetails.append("\tWARNING: EXPIRED ");
        
        certDetails.append("\tIssuer: ");
        certDetails.append(cIssuer);
        certDetails.append(" Subject: ");
        certDetails.append(cSubject);
        certDetails.append(" From: ");
        certDetails.append(cStart);
        certDetails.append(" To: ");
        certDetails.append(cEnd);
        System.out.println(certDetails.toString());
        
        SimpleKeySelector sks = new SimpleKeySelector();
        sks.setFixedKey(x.getPublicKey());
        
        DOMStructure sig = new DOMStructure(signatureNode); 
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new CharArrayReader(rx.toCharArray())));
        Node n = doc.getElementsByTagName("FragmentsToBeHashed").item(0);
        XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
        DOMValidateContext dvc = new DOMValidateContext(sks, n);
        dvc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        dvc.setURIDereferencer(urid);
        XMLSignature xmlsig = xsf.unmarshalXMLSignature(sig);
        boolean isvalid = xmlsig.validate(dvc);
        
        if (!isvalid) {
            boolean sigvalid = xmlsig.getSignatureValue().validate(dvc);
            if (sigvalid) {
                StringBuilder sbInvalid = new StringBuilder(fname);
                sbInvalid.append("\tFAILED\tValidation failed: ");
                java.util.Iterator it = xmlsig.getSignedInfo().getReferences().iterator();
                for (int j = 0; it.hasNext(); j++) {
                    Reference refr = (Reference)it.next();
                    boolean refValid = refr.validate(dvc);
                    if (!refValid) {                       
                        sbInvalid.append("\tReference ");
                        sbInvalid.append(j);
                        sbInvalid.append(" is invalid:\t");
                        java.io.InputStreamReader sis = new java.io.InputStreamReader(refr.getDigestInputStream());
                        char[] b = new char[10240];
                        int r = sis.read(b);
                        if (r != -1) {
                            sbInvalid.append(new String(b, 0, r));
                        } else {
                            sbInvalid.append("Failed to read reference");
                        }
                        // TODO: Fix this and stop it dumping the unfilled part of the buffer
                        System.out.println(sbInvalid.toString());
                    }
                }
            } else {                
                System.out.println(fname + "\tFAILED\tInvalid signature for valid digest");
            }
        }
        
        return isvalid;
    }
    
}
