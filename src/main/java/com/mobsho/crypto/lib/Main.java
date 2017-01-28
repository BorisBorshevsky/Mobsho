package com.mobsho.crypto.lib;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Optional;


public class Main {


    private enum OperationType {
        Encrypt("encrypt"),
        Decrypt("decrypt");

        private final String text;

        OperationType(String text) {
            this.text = text;
        }

        public String getText() {
            return this.text;
        }

        public static OperationType fromString(String text) {
            if (text != null) {
                for (OperationType b : OperationType.values()) {
                    if (text.equalsIgnoreCase(b.getText())) {
                        return b;
                    }
                }
            }
            return null;
        }
    }


    public static void main(String[] args) {

        if (args.length != 7) {
            System.out.println("Bad Input.");
            System.out.print("args: <Operation mode> <input filename> <output filename> <keyStore filename> <keyStore password> <private key alias> <public key alias>");
            return;
        }

        String inputFile = args[1];
        String outputFile = args[2];
        String keyStore = args[3];
        String privateKeyAlias = args[4];
        String keyStorePassword = args[5];
        String publicKeyAlias = args[6];

        try {
            switch (OperationType.fromString(args[0])) {
                case Decrypt:
                    decryptNow(inputFile, outputFile, keyStore, keyStorePassword, privateKeyAlias, publicKeyAlias);
                    break;
                case Encrypt:
                    encryptNow(inputFile, outputFile, keyStore, keyStorePassword, privateKeyAlias, publicKeyAlias);
                    break;
                default:
                    System.out.println("Bad Operation mode. choose [decrypt, encrypt].");
                    System.exit(1);
            }

            System.out.println("Program Ended successfully");
            System.exit(0);
        } catch (IOException ioe) {
            System.out.println("Program failed: " + ioe.getMessage());
            System.out.println("please check that the required files exist.");
            System.exit(1);
        } catch (Exception e) {
            System.out.println("Program failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void decryptNow(String filename, String outputFile, String keyStore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws Exception {
        try {
            Decryptor decryptor = new Decryptor(new KeyStoreHelper(keyStore, keystorePassword));
            decryptor.DecryptAndVerifyFile(filename, outputFile, myPrivateKeyAlias, theirPublicKeyAlias);
        } catch (Exception e) {
            FileOutputStream fos = new FileOutputStream(outputFile);
            fos.write(("Error!!!! " + e.getMessage()).getBytes());
            throw e;
        }
    }

    private static void encryptNow(String filename, String outputFile, String keyStore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {
        Encryptor encryptor = new Encryptor(new KeyStoreHelper(keyStore, keystorePassword));
        FileOutputStream fos = new FileOutputStream(outputFile);
        EncryptionProcessContext option = encryptor.EncryptFile(filename, fos, myPrivateKeyAlias, theirPublicKeyAlias, Optional.empty(), Optional.empty());
        DigitalSigner digitalSigner = new DigitalSigner();
        option.setSignature(digitalSigner.sign(filename, option.myPrivateKey));

        ConfigurationManager confManager = new ConfigurationManager(option.cipher.getParameters().getEncoded(), Utils.EncryptRsa(option.getSecretKey().getEncoded(), option.theirPublicKey), option.signature);
        confManager.dumpToFile();
    }


}
