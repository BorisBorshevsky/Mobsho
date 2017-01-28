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

    /**
     * @param args: <Operation mode> <data filename> <keystore filename> <keystore password> <private key alias> <private key password> <public key alias>
     */


    public enum RunningType {
        Encryptor("encrypt"),
        Decryptor("decrypt");

        private String text;

        RunningType(String text) {
            this.text = text;
        }

        public String getText() {
            return this.text;
        }

        public static RunningType fromString(String text) {
            if (text != null) {
                for (RunningType b : RunningType.values()) {
                    if (text.equalsIgnoreCase(b.getText())) {
                        return b;
                    }
                }
            }
            return null;
        }
    }


    public static void main(String[] args) throws Exception {
        ArrayList<String> argsSend = new ArrayList<String>();
        argsSend.add("encrypt");
        argsSend.add("data.txt");
        argsSend.add("A/storeA.jks");
        argsSend.add("keyA");
        argsSend.add("passwordA");
        argsSend.add("keyB");

        String[] stockArr = new String[argsSend.size()];
        stockArr = argsSend.toArray(stockArr);


        ArrayList<String> argsSend1 = new ArrayList<String>();
        argsSend1.add("decrypt");
        argsSend1.add("data1.enc");
        argsSend1.add("B/storeB.jks");
        argsSend1.add("keyB");
        argsSend1.add("passwordB");
        argsSend1.add("keyA");

        String[] stockArr1 = new String[argsSend1.size()];
        stockArr1 = argsSend1.toArray(stockArr1);

//        main2(stockArr);  // encrypt
        main2(stockArr1); //dcryptt
    }

    public static void main2(String[] args) {

        if (args.length != 7) {
            System.out.println("Wrong number of arguments given. Please try again.");
            return;
        }

		/*Prepare keynames, passwords and filenames*/
        String filename = args[1];
        String keystore = args[2];
        String keystorePassword = args[3];
        String myPrivateKeyAlias = args[4];
        String theirPublicKeyAlias = args[5];


        String[] algorithmValues = chooseYourOwnImpementation(1);

        try {
            switch (RunningType.fromString(args[0])) {
                case Decryptor:
//                    decrypt(filename, keystore, keystorePassword, myPrivateKeyAlias, myPrivateKeyPassword, theirPublicKeyAlias);
                        decryptNow(filename,keystore,keystorePassword,myPrivateKeyAlias,theirPublicKeyAlias);
                    break;
                case Encryptor:
//                    encrypt(filename, keystore, keystorePassword, myPrivateKeyAlias, myPrivateKeyPassword, theirPublicKeyAlias, algorithmValues);
                    encryptNow(filename, keystore, keystorePassword, myPrivateKeyAlias, theirPublicKeyAlias);
                    break;
                default:
                    System.out.println("Wrong operation mode. Please try again.");
                    System.exit(1);
            }

            System.out.println("Program Ended successfully");
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Program failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void decrypt(String filename, String keystore, String keystorePassword, String myPrivateKeyAlias, String myPrivateKeyPassword, String theirPublicKeyAlias) {
        int status;/*Receiver - decrypt & verify*/
        DecryptAndVerify decVerEngine = new DecryptAndVerify(keystore, keystorePassword);
        status = decVerEngine.DecryptAndVerifyFile(myPrivateKeyAlias, myPrivateKeyPassword, theirPublicKeyAlias, filename);
        if (status == 0) {
            System.out.println("Program succeeded: Your file was decrypted and verified and is now ready.");
            System.out.println("Output file: data.dec");
        }
        //todo: if error throw exception

    }

    public static void decryptNow(String filename, String keystore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, ParserConfigurationException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SAXException, NoSuchPaddingException, KeyStoreException, SignatureException {
        Decryptor decryptor = new Decryptor(new KeyStoreHelper(keystore, keystorePassword));
        decryptor.DecryptAndVerifyFile("data1.enc", "data1.dec", myPrivateKeyAlias, theirPublicKeyAlias);


    }


    private static void encrypt(String filename, String keystore, String keystorePassword, String myPrivateKeyAlias, String myPrivateKeyPassword, String theirPublicKeyAlias, String[] algorithmValues) {
        int status;/*Sender - encrypt & sign*/
            /*EncryptAndSign encSignEngine = new EncryptAndSign("ReceiverPair.jks", "password");*/
        EncryptAndSign encSignEngine = new EncryptAndSign(keystore, keystorePassword, algorithmValues);
        status = encSignEngine.encryptAndSignFile(myPrivateKeyAlias, theirPublicKeyAlias, filename);
        if (status == 0) {
            System.out.println("Program succeeded: Your file is encrypted and signed.");
            System.out.println("Output files: data.enc, configuration.xml");
        }

        //todo: if error throw exception
    }

    private static void encryptNow(String filename, String keystore, String keystorePassword, String myPrivateKeyAlias, String theirPublicKeyAlias) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, SignatureException, BadPaddingException, IllegalBlockSizeException, TransformerException, ParserConfigurationException {
        Encryptor encryptor = new Encryptor(new KeyStoreHelper(keystore, keystorePassword));
        FileOutputStream fos = new FileOutputStream("data1.enc");
        EncryptionProcessContext option = encryptor.EncryptFile(filename, fos, myPrivateKeyAlias, theirPublicKeyAlias, Optional.empty(), Optional.empty());
        DigitalSigner digitalSigner = new DigitalSigner();
        option.setSignature(digitalSigner.sign(filename, option.myPrivateKey));

        ConfigurationManager xmlhandler = new ConfigurationManager(option.cipher.getParameters().getEncoded(), utils.EncryptRsa(option.getSecretKey().getEncoded(), option.theirPublicKey), option.signature);
        xmlhandler.createConfigurationFile();
    }



        public static String[] chooseYourOwnImpementation(int mode) {
        String s;

        String values[] = new String[4];

        values[0] = "AES/CBC/PKCS5Padding";
        values[1] = "Default";
        values[2] = "SHA1withRSA";
        values[3] = "Default";

        return values;
//
//        Scanner in = new Scanner(System.in);
//
//        System.out.println("Welcome to ProGram.");
//
//        if (mode == 0) {
//            System.out.println("Chosen mode is: send");
//        } else if (mode == 1) {
//            System.out.println("Chosen mode is: receive");
//        }
//        System.out.println("Default values are: ");
//        System.out.println("Chiper - algorithm: " + values[0] + ", provider: " + values[1]);
//        System.out.println("Signature - algorithm: " + values[2] + ", provider: " + values[3]);
//        System.out.println("\nWould you like to change default Algorithms or providers? [Y/N]");
//        s = in.nextLine();
//        if ((s.contentEquals("n")) || (s.contentEquals("N"))) {
//            System.out.println("Running with default values.");
//            return values;
//        } else if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//            System.out.println("Would you like to change the Cipher (encryption/decryption) values? [Y/N]");
//            s = in.nextLine();
//            if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                System.out.println("Would you like to change the cipher Algorithm? [Y/N]");
//                s = in.nextLine();
//                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                    System.out.println("Please enter cipher algorithm string: ");
//                    values[0] = new String(in.nextLine());
//                    System.out.println("You entered: " + values[0]);
//                }
//                System.out.println("Would you like to change the cipher Provider? [Y/N]");
//                s = in.nextLine();
//                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                    System.out.println("Please enter cipher provider string: ");
//                    values[1] = new String(in.nextLine());
//                    System.out.println("You entered: " + values[1]);
//                }
//            } else if ((s.contentEquals("n")) || (s.contentEquals("N"))) {
//
//            } else {
//                System.out.println("Wrong input! Using default values.");
//                return values;
//            }
//
//            System.out.println("Would you like to change the signature (signature/verification) values? [Y/N]");
//            s = in.nextLine();
//            if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                System.out.println("Would you like to change the signature Algorithm? [Y/N]");
//                s = in.nextLine();
//                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                    System.out.println("Please enter signature algorithm string: ");
//                    values[0] = new String(in.nextLine());
//                    System.out.println("You entered: " + values[2]);
//                }
//                System.out.println("Would you like to change the signature Provider? [Y/N]");
//                s = in.nextLine();
//                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
//                    System.out.println("Please enter signature provider string: ");
//                    values[3] = new String(in.nextLine());
//                    System.out.println("You entered: " + values[3]);
//                }
//            } else if ((s.contentEquals("n")) || (s.contentEquals("N"))) {
//
//            } else {
//                System.out.println("Wrong input! Using default values.");
//                return values;
//            }
//        } else {
//            System.out.println("Wrong input! Using default values.");
//            return values;
//        }
//
//        System.out.println("Chosen values for current session are:");
//        System.out.println("Chiper - algorithm: " + values[0] + ", provider: " + values[1]);
//        System.out.println("Signature - algorithm: " + values[2] + ", provider: " + values[3]);
//
//        return values;
    }

}
