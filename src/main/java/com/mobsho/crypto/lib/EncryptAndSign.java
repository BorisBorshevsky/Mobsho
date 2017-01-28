package com.mobsho.crypto.lib;

import java.security.Key;
import java.security.PublicKey;

public class EncryptAndSign {

    ChipherImpl ChiperHandler;
    DigitalSignatureImpl digitalSignatureHandler;
    KeyStoreHelper keyStoreHelper;
    String cipherAlgorithm;
    String cipherProvider;
    String signatureAlgorithm;
    String signatureProvider;
    String[] algorithmValues;

    public EncryptAndSign(String keyStoreFilename, String keyStorePassword, String[] values) {
        this.ChiperHandler = new ChipherImpl();
        this.digitalSignatureHandler = new DigitalSignatureImpl();
        this.keyStoreHelper = new KeyStoreHelper(keyStoreFilename, keyStorePassword);
        this.algorithmValues = values;
    }

    public int encryptAndSignFile(String myPrivateKeyAlias, String theirPublicKeyAlias, String inputFileName) {

        //QAQA - Must get passwords from user.
        try {
            //Load keys - 1st for asymetric encryption, 2nd for asymetric digital signing
            //Load the other side's asymetric public key
            PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);

            //Load my asymetric private key for digital signature
            Key myAsymetricPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);


            //Encrypt file "inputFileName" content and save in "EncryptedData". Save encryption configuration in "configFile".
//            if (algorithmValues[0].compareTo("AES/CBC/PKCS5Padding") != 0) {
//                ChiperHandler.setCipherAlgorithm(algorithmValues[0]);
//            }

//            if (algorithmValues[1].compareTo("Default") != 0) {
//                ChiperHandler.setCipherProvider(algorithmValues[1]);
//            }

            byte[] encodedAlgorithmParametres = this.ChiperHandler.encryptFile(inputFileName);
            if (encodedAlgorithmParametres == null) {
                System.out.println("Failed encrypting file. Exiting program.");
                return -1;
            }

            //Encrypt the private key used for encryption in "encryptedPrivateKeyFile"
            byte[] encryptedPrivateKey = this.ChiperHandler.encryptPrivateKey(theirPublicKey);
            if (encryptedPrivateKey == null) {
                System.out.println("Failed encrypting private key. Exiting program.");
                return -1;
            }

            //Sign original file
//            if (algorithmValues[2].compareTo("AES/CBC/PKCS5Padding") != 0)
//                digitalSignatureHandler.setSignatureAlgorithm(algorithmValues[2]);
//            if (algorithmValues[3].compareTo("Default") != 0)
//                digitalSignatureHandler.setSignatureProvider(algorithmValues[3]);
            byte[] signature = digitalSignatureHandler.signData(inputFileName, myAsymetricPrivateKey);
            if (signature == null) {
                System.out.println("Failed signing file. Exiting program.");
                return -1;
            }

            //Save all parameters in a XML configuration file
            ConfigurationManager xmlhandler = new ConfigurationManager(encodedAlgorithmParametres, encryptedPrivateKey, signature);
            xmlhandler.createConfigurationFile();

        } catch (Exception e1) {
            e1.printStackTrace();
        }

        return 0;
    }

}
