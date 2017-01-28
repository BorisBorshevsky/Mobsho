package com.mobsho.crypto.lib;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

/**
 * Created by boris on 1/28/17.
 */
public class DigitalSignatureVerifier {

    public static void verifySignature(byte[] signature, String inputFile, PublicKey theirPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        //Initialize the Signature Object for Verification
        Signature sig;
        //Get a Signature Object
        sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(theirPublicKey);

        //Verify the Signature
        //Supply the Signature Object With the Data to be Verified
        FileInputStream datafis = new FileInputStream(inputFile);
        BufferedInputStream bufin = new BufferedInputStream(datafis);

        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            sig.update(buffer, 0, len);
        }

        bufin.close();
        datafis.close();

        //Verify the Signature
        boolean verifies = sig.verify(signature);
        System.out.println("******************************");
        if (verifies) {
            System.out.println("Signature is valid! :)");
        } else {
            System.out.println("Signature is NOT valid NOT valid NOT valid");
        }
        System.out.println("******************************");


    }
}
