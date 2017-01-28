package com.mobsho.crypto.lib;

import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;


public class Decryptor {
    static final String DEFAULT_ALGORITHM = "AES/CBC/PKCS5Padding";


    KeyStoreHelper keyStoreHelper;

    public Decryptor(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }


    public void DecryptAndVerifyFile(String encryptedFileName, String outputFile, String myPrivateKeyAlias, String theirPublicKeyAlias) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParserConfigurationException, SAXException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {

        PrivateKey myPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);
        PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);


        //Extract parameters from the XML configuration file
        ConfigurationManager xmlhandler = new ConfigurationManager();
        xmlhandler.parseConfigurationFile();
        byte[] encodedAlgorithmParametres = xmlhandler.getAlgorithmParameters();
        byte[] encryptedSecretKey = xmlhandler.getEncryptedSecretKey();
        byte[] digitalSignature = xmlhandler.getDigitalSignature();

        //Decrypt/extract private key
        byte[] secretKeyBytes = utils.DecryptRsa(encryptedSecretKey, myPrivateKey);
        SecretKeySpec secret = new SecretKeySpec(secretKeyBytes, "AES");

        this.decryptFile(encryptedFileName, outputFile, encodedAlgorithmParametres, secret);

        //Verify file by signature
        DigitalSignatureVerifier.verifySignature(digitalSignature, outputFile, theirPublicKey);
    }

    public void decryptFile(String encryptedFile, String decryptedOutputFile, byte[] encodedAlgParams, SecretKey sKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        FileInputStream fis;
        FileOutputStream fos;
        CipherInputStream cis;
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

        //Close resources
        fis.close();
        fos.close();
        cis.close();


    }


}
