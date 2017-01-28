package com.mobsho.crypto.lib;

import org.xml.sax.SAXException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
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
            System.out.println("Wrong number of arguments given. Please try again.");
            System.out.print("args: <Operation mode> <data filename> <keystore filename> <keystore password> <private key alias> <public key alias>");
            return;
        }

		/*Prepare keynames, passwords and filenames*/
        String filename = args[1];
        String keystore = args[3];
        String keystorePassword = args[5];
        String myPrivateKeyAlias = args[4];
        String theirPublicKeyAlias = args[6];
        String outputFile = args[2];

        try {
            switch (OperationType.fromString(args[0])) {
                case Decrypt:
                    decryptNow(filename, outputFile, keystore, keystorePassword, myPrivateKeyAlias, theirPublicKeyAlias);
                    break;
                case Encrypt:
                    encryptNow(filename, outputFile, keystore, keystorePassword, myPrivateKeyAlias, theirPublicKeyAlias);
                    break;
                default:
                    System.out.println("Bad Operation mode. choose [decrypt, encrypt].");
                    System.exit(1);
            }

            System.out.println("Program Ended successfully");
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Program failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void decryptNow(String filename, String outputFile, String keystore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws Exception {
        Decryptor decryptor = new Decryptor(new KeyStoreHelper(keystore, keystorePassword));
        decryptor.DecryptAndVerifyFile(filename, outputFile, myPrivateKeyAlias, theirPublicKeyAlias);
    }

    private static void encryptNow(String filename, String outputFile, String keystore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {
        Encryptor encryptor = new Encryptor(new KeyStoreHelper(keystore, keystorePassword));
        FileOutputStream fos = new FileOutputStream(outputFile);
        EncryptionProcessContext option = encryptor.EncryptFile(filename, fos, myPrivateKeyAlias, theirPublicKeyAlias, Optional.empty(), Optional.empty());
        DigitalSigner digitalSigner = new DigitalSigner();
        option.setSignature(digitalSigner.sign(filename, option.myPrivateKey));

        ConfigurationManager xmlhandler = new ConfigurationManager(option.cipher.getParameters().getEncoded(), Utils.EncryptRsa(option.getSecretKey().getEncoded(), option.theirPublicKey), option.signature);
        xmlhandler.createConfigurationFile();
    }


}
