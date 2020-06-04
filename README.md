# PrescriptionSignatureTools256
Java sources for NHS Digital test prescription signing, and signature verification

This is the package used by NHS Digital's Test Data and Solution Assurance teams for signing test prescriptions, and for verifying signatures. It is a development of the original "PrescriptionSignatureTools" that was based on JKS keystores and only supported SHA1/RSA_SHA1 signatures. This version supports PKCS#12 and JKS and will also generate SHA256/RSA_SHA256 signatures. Note that the signing capability of this software is based on file-based cryptographic material and it does NOT sign using NHS Digital smart cards.

This has been built and tested using Apache Netbeans 11 on JDK13. The only other dependency is the Saxon (HE) XSLT engine included in the POM.

Once built it is used with the command-line parameters:

operation propertiesfile

Where "operation" is one of "sign" or "verify". Example properties files are given in the source /propertiesexamples package at https://github.com/DamianJMurphy/PrescriptionSignatureTools256/tree/master/src/main/java/propertiesexamples

So for example using the "pst2verify.properties" file from the examples, put the prescription files to be verified into ./input and run:

java -jar PrescriptionSignatureTools256.jar verify pst2verify.properties

Verification details are written to stdout.
