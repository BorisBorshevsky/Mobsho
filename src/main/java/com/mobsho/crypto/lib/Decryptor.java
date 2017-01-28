package com.mobsho.crypto.lib;

import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;


class Decryptor {
    private static final String DEFAULT_ALGORITHM = "AES/CBC/PKCS5Padding";

    private final KeyStoreHelper keyStoreHelper;

    public Decryptor(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }


    public void DecryptAndVerifyFile(String encryptedFileName, String outputFile, String myPrivateKeyAlias, String theirPublicKeyAlias) throws Exception {

        PrivateKey myPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);
        PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);


        //Extract parameters from the XML configuration file
        ConfigurationManager configManager = new ConfigurationManager();
        configManager.parseConfigurationFile();
        byte[] encodedAlgorithmParameters = configManager.getAlgorithmParameters();
        byte[] encryptedSecretKey = configManager.getEncryptedSecretKey();
//

        //Decrypt/extract private key
        byte[] secretKeyBytes = Utils.DecryptRsa(encryptedSecretKey, myPrivateKey);
        SecretKeySpec secret = new SecretKeySpec(secretKeyBytes, "AES");


        //decrypt file
        this.decryptFile(encryptedFileName, outputFile, encodedAlgorithmParameters, secret);


        //Verify file by signature
        byte[] digitalSignature = configManager.getDigitalSignature();
        DigitalSignatureVerifier.verifySignature(digitalSignature, outputFile, theirPublicKey);
    }

    private void decryptFile(String encryptedFile, String decryptedOutputFile, byte[] encodedAlgParams, SecretKey sKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        FileInputStream fis = null;
        FileOutputStream fos = null;
        CipherInputStream cis = null;
        try {

            AlgorithmParameters algParams;
            Cipher myCipher;


            algParams = AlgorithmParameters.getInstance("AES");
            // initialize with parameter encoding from above
            algParams.init(encodedAlgParams);
            myCipher = Cipher.getInstance(DEFAULT_ALGORITHM);
            myCipher.init(Cipher.DECRYPT_MODE, sKey, algParams);

            fis = new FileInputStream(encryptedFile);
            fos = new FileOutputStream(decryptedOutputFile);
            cis = new CipherInputStream(fis, myCipher);

            byte[] buffer = new byte[8];
            int i = cis.read(buffer);

            //write loop
            while (i != -1) {
                fos.write(buffer, 0, i);
                i = cis.read(buffer);
            }
        } finally {
            if (fis != null) fis.close();
            if (fos != null)fos.close();
            if (cis != null)cis.close();

        }
        //Close resources


    }


}
