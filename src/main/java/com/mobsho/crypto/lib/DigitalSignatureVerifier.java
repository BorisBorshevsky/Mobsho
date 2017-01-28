package com.mobsho.crypto.lib;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Signature;

import static com.mobsho.crypto.lib.DigitalSigner.DEFAULT_SIGNATURE_ALGO;

/**
 * Created by boris on 1/26/17.
 */
class DigitalSignatureVerifier {

    public static void verifySignature(byte[] signature, String inputFile, PublicKey theirPublicKey) throws Exception {
        //Initialize the Signature Object for Verification
        Signature sig;
        //Get a Signature Object
        sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGO);
        sig.initVerify(theirPublicKey);

        //Verify the Signature
        //Supply the Signature Object With the Data to be Verified
        FileInputStream dataFis = new FileInputStream(inputFile);
        BufferedInputStream bufferedIs = new BufferedInputStream(dataFis);

        byte[] buffer = new byte[1024];
        int len;
        while (bufferedIs.available() != 0) {
            len = bufferedIs.read(buffer);
            sig.update(buffer, 0, len);
        }

        bufferedIs.close();
        dataFis.close();

        //Verify the Signature
        boolean verifies = sig.verify(signature);
        if (!verifies) {
            throw new Exception("Signature is NOT valid");
        }
    }
}
