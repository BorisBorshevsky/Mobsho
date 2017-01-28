package com.mobsho.crypto.lib;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Optional;

/**
 * Created by boris on 1/28/17.
 */
public class DigitalSigner {
    private String signAlgorithm;
    private Optional<String> signProvider;

    public DigitalSigner() {
        this(Optional.empty(), Optional.empty());
    }

    public DigitalSigner(Optional<String> signAlgorithm, Optional<String> signProvider) {
        this.signAlgorithm = signAlgorithm.orElse("SHA1withRSA");
        this.signProvider = signProvider;
    }

    public byte[] sign(String inputFile, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {
        Signature signature;
        if (this.signProvider.isPresent()) {
            signature = Signature.getInstance(this.signAlgorithm, this.signProvider.get());
        } else {
            signature = Signature.getInstance(this.signAlgorithm);
        }

        signature.initSign(privateKey);

        //Supply the Signature Object the Data to Be Signed
        FileInputStream fis = new FileInputStream(inputFile);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0) {
            signature.update(buffer, 0, len);
        }

        bufin.close();

        //Generate the Signature
        return signature.sign();
    }

    public boolean verify() {
        return true;
    }
}
