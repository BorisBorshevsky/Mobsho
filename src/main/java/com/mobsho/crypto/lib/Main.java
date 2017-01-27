package com.mobsho.crypto.lib;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;


public class Main {

    /**
     * @param args: <Operation mode> <data filename> <keystore filename> <keystore password> <private key alias> <private key password> <public key alias>
     */


    public static void main(String[] args) throws Exception{
        ArrayList<String> argsSend = new ArrayList<String>();
        argsSend.add("send");
        argsSend.add("data.txt");
        argsSend.add("A/storeA.jks");
        argsSend.add("passwordA");
        argsSend.add("keyA");
        argsSend.add("passwordA");
        argsSend.add("keyB");

        String[] stockArr = new String[argsSend.size()];
        stockArr = argsSend.toArray(stockArr);

        main2(stockArr);
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
        String myPrivateKeyPassword = args[5];
        String theirPublicKeyAlias = args[6];

        int status = 0;

        String[] algorithmValues = chooseYourOwnImpementation(1);
			
		/*Check operation mode and */
        if (args[0].equals("send")) {
			/*Sender - encrypt & sign*/
			/*EncryptAndSign encSignEngine = new EncryptAndSign("ReceiverPair.jks", "password");*/
            EncryptAndSign encSignEngine = new EncryptAndSign(keystore, keystorePassword, algorithmValues);
            status = encSignEngine.encryptAndSignFile(myPrivateKeyAlias, myPrivateKeyPassword, theirPublicKeyAlias, filename);
            if (status == 0) {
                System.out.println("Program succeeded: Your file is encrypted and signed.");
                System.out.println("Output files: data.enc, configuration.xml");
                return;
            }
        } else if (args[0].equals("receive")) {
			/*Receiver - decrypt & verify*/
            DecryptAndVerify decVerEngine = new DecryptAndVerify(keystore, keystorePassword);
            status = decVerEngine.DecryptAndVerifyFile(myPrivateKeyAlias, myPrivateKeyPassword, theirPublicKeyAlias, filename);
            if (status == 0) {
                System.out.println("Program succeeded: Your file was decrypted and verified and is now ready.");
                System.out.println("Output file: data.dec");
                return;
            }
        } else {
            System.out.println("Wrong operation mode. Please try again.");
        }


        System.out.println("Program failed. Try again!");
    }


    public static String[] chooseYourOwnImpementation(int mode) {
        String s;

        String values[] = new String[4];

        values[0] = new String("AES/CBC/PKCS5Padding");
        values[1] = new String("Default");
        values[2] = new String("SHA1withRSA");
        values[3] = new String("Default");

        Scanner in = new Scanner(System.in);

        System.out.println("Welcome to ProGram.");

        if (mode == 0) {
            System.out.println("Chosen mode is: send");
        } else if (mode == 1) {
            System.out.println("Chosen mode is: receive");
        }
        System.out.println("Default values are: ");
        System.out.println("Chiper - algorithm: " + values[0] + ", provider: " + values[1]);
        System.out.println("Signature - algorithm: " + values[2] + ", provider: " + values[3]);
        System.out.println("\nWould you like to change default Algorithms or providers? [Y/N]");
        s = in.nextLine();
        if ((s.contentEquals("n")) || (s.contentEquals("N"))) {
            System.out.println("Running with default values.");
            return values;
        } else if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
            System.out.println("Would you like to change the Cipher (encryption/decryption) values? [Y/N]");
            s = in.nextLine();
            if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                System.out.println("Would you like to change the cipher Algorithm? [Y/N]");
                s = in.nextLine();
                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                    System.out.println("Please enter cipher algorithm string: ");
                    values[0] = new String(in.nextLine());
                    System.out.println("You entered: " + values[0]);
                }
                System.out.println("Would you like to change the cipher Provider? [Y/N]");
                s = in.nextLine();
                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                    System.out.println("Please enter cipher provider string: ");
                    values[1] = new String(in.nextLine());
                    System.out.println("You entered: " + values[1]);
                }
            } else if ((s.contentEquals("n")) || (s.contentEquals("N"))) {

            } else {
                System.out.println("Wrong input! Using default values.");
                return values;
            }

            System.out.println("Would you like to change the signature (signature/verification) values? [Y/N]");
            s = in.nextLine();
            if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                System.out.println("Would you like to change the signature Algorithm? [Y/N]");
                s = in.nextLine();
                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                    System.out.println("Please enter signature algorithm string: ");
                    values[0] = new String(in.nextLine());
                    System.out.println("You entered: " + values[2]);
                }
                System.out.println("Would you like to change the signature Provider? [Y/N]");
                s = in.nextLine();
                if ((s.contentEquals("y")) || (s.contentEquals("Y"))) {
                    System.out.println("Please enter signature provider string: ");
                    values[3] = new String(in.nextLine());
                    System.out.println("You entered: " + values[3]);
                }
            } else if ((s.contentEquals("n")) || (s.contentEquals("N"))) {

            } else {
                System.out.println("Wrong input! Using default values.");
                return values;
            }
        } else {
            System.out.println("Wrong input! Using default values.");
            return values;
        }

        System.out.println("Chosen values for current session are:");
        System.out.println("Chiper - algorithm: " + values[0] + ", provider: " + values[1]);
        System.out.println("Signature - algorithm: " + values[2] + ", provider: " + values[3]);

        return values;
    }

}
