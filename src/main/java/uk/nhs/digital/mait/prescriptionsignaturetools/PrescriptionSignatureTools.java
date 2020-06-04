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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

/**
 *
 * @author DAMU2
 */
public class PrescriptionSignatureTools {

    private static final String OP_SIGN = "sign";
    private static final String OP_VERIFY = "verify";
    private static final String OP_CHECK = "check";
    private static final String OP_RR = "rrverify";

    static final int UNDEFINED = 0;
    static final int SIGN = 1;
    static final int VERIFY = 2;
    static final int CHECK = 3;
    static final int RRVERIFY = 4;

    public static final String KEYSTORE = "uk.nhs.digital.mait.prescriptionsignature.keystore";
    public static final String USERID = "uk.nhs.digital.mait.prescriptionsignature.userid"; 
    public static final String PASSWORD = "uk.nhs.digital.mait.prescriptionsignature.password";
    
    public static final String INDIR = "uk.nhs.digital.mait.prescriptionsignature.inputdirectory";
    public static final String OUTDIR = "uk.nhs.digital.mait.prescriptionsignature.outputdirectory";
    
    public static final String THREAD = "uk.nhs.digital.mait.prescriptionsignature.multithread";
    public static final String STOP = "uk.nhs.digital.mait.prescriptionsignature.stoponerror";
    
    public static final String UTFSUBSTITUTIONROOT = "uk.nhs.digital.mait.prescriptionsignature.utfsubstitution.";
    
    private int operation = UNDEFINED;
    private Properties properties = null;
    private CryptoProviderFactory cryptoProviderFactory = null;
    private boolean multiThread = false;
    private boolean stopOnError = false;
    private String inputDirectory = null;
    private String outputDirectory = null;
    private int threadCount = 1;
    
    private HashMap<String,String> utfSubstitutions = null;
    
    
    @SuppressWarnings("ConvertToTryWithResources")
    public PrescriptionSignatureTools(int op, String pfile)
            throws Exception
    {        
        operation = op;
        if (pfile != null) {
           try {
                FileInputStream fis = new FileInputStream(pfile);
                properties = new Properties();
                properties.load(fis);
                fis.close();
           }
           catch (IOException e) {
               System.err.println(e.getMessage());
               return;
           }
        }
        
        String ks = null;
        String u = null;
        String p = null;
        
        if (properties != null) {
            ks = properties.getProperty(KEYSTORE);
            u = properties.getProperty(USERID);
            p = properties.getProperty(PASSWORD);
            @SuppressWarnings("UnusedAssignment")
            String prop = null;
            prop = properties.getProperty(THREAD);
            if (prop != null) {
                multiThread = prop.toLowerCase().startsWith("y");                                
            }
            inputDirectory = properties.getProperty(INDIR);
            outputDirectory = properties.getProperty(OUTDIR);
            prop = properties.getProperty(STOP);
            if (prop != null) {
                stopOnError = prop.toLowerCase().startsWith("y");
            }
            buildSubstitutions(properties);
        }
        cryptoProviderFactory = new CryptoProviderFactory(properties, stopOnError, (op == VERIFY));
    }
    
    private void buildSubstitutions(Properties p) 
            throws Exception
    {
        if (p == null)
            return;
        Enumeration<Object> keys = p.keys();
        while (keys.hasMoreElements()) {
            String s = (String)keys.nextElement();
            if (s.startsWith(UTFSUBSTITUTIONROOT)) {
                String sub = s.substring(s.lastIndexOf(".") + 1);
                if (utfSubstitutions == null)
                    utfSubstitutions = new HashMap<>();
                String u = hexToUnicodePoint((String)p.getProperty(s));
                utfSubstitutions.put(sub, u);
            }
        }
    }
    
    private String hexToUnicodePoint(String s)
            throws Exception
    {        
        int cp[] = new int[1];
        cp[0] = Integer.parseInt(s, 16);
        return new String(cp, 0, 1);
    }
    
    public static int resolveOperation(String op) {
        if (op == null) {
            return UNDEFINED;
        }
        if (op.contentEquals(OP_SIGN)) {
            return SIGN;
        }
        if (op.contentEquals(OP_VERIFY)) {
            return VERIFY;
        }
//        if (op.contentEquals(OP_CHECK)) {
//            return CHECK;
//        }
        if (op.contentEquals(OP_RR)) {
            return RRVERIFY;
        }
        return UNDEFINED;
    }
  
    public void signerEnd() {
       threadCount--;
       if (threadCount == 0) {
           System.out.println("All threads done");
       }
    }
    
    public void go() 
            throws Exception
    {
        if (properties == null)
            return;
        
        // Get the input directory. See if threading is enabled. If it is,
        // split up directory content into number of processors and start
        // that number of Signers. Dispatch the files amongst the signers.
        
        if (multiThread) {
            threadCount = Runtime.getRuntime().availableProcessors();
        }
        File inDir = new File(inputDirectory);
        if (!inDir.exists()) {
           throw new Exception("Input directory " + inputDirectory + " not found");
        }
        if (!inDir.isDirectory()) {
           throw new Exception("Input directory " + inputDirectory + " not found");
        }
        File[] rxFiles = inDir.listFiles();
        // Create the signers
        Signer[] signers = new Signer[threadCount];        
        for (int i = 0; i < threadCount; i++) {
            switch (operation) {
                case VERIFY:
                case RRVERIFY:
                    signers[i] = new Signer(null, operation, null);
                    break;
                case SIGN:
                    signers[i] = new Signer(outputDirectory, operation, utfSubstitutions);
                    break;
                default:
                    break;
            }        
            signers[i].setCryptoProviderFactory(cryptoProviderFactory);
            signers[i].setTool(this);
            if (stopOnError) {
                signers[i].setStopOnError();
            }
        }
        // Distribute the Rx files across the signers
        for (int i = 0; i < rxFiles.length;) {
            for (int j = 0; j < threadCount; j++) {                
                signers[j].addFile(rxFiles[i]);
                i++;
                if (i == rxFiles.length) {
                    break;
                }
            }
        }
        // Start the threads
        for (int i = 0; i < threadCount; i++) {
            signers[i].start();
        }        
    }    
    
    /**
     * @param args the command line arguments
     */
    @SuppressWarnings("CallToPrintStackTrace")
    public static void main(String[] args) {
        try {
            System.setOut(new PrintStream(System.out, true, "US-ASCII"));
        }
        catch(UnsupportedEncodingException e) {
            System.out.println("Doesn't seem to want to do ASCII output!");
        }
        try {
            @SuppressWarnings("UnusedAssignment")
            int op = UNDEFINED;
            @SuppressWarnings("UnusedAssignment")
            String pfile = null;
            if (args.length == 2) {
                op = resolveOperation(args[0]);
                if (op == UNDEFINED) {
                    System.err.println("Error: Unknown operation: " + args[0]);
                    System.exit(1);
                }                    
                pfile = args[1];
            } else {
                System.err.println("Usage: java -jar PrescriptionSignatureTools.jar operation propertiesfile\nWhere \"operation\" one of SIGN or VERIFY\n");
                System.exit(1);                    
            }
            PrescriptionSignatureTools pst = new PrescriptionSignatureTools(op, pfile);
            pst.go();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
