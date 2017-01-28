package com.mobsho.crypto.lib;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by boris on 1/26/17.
 */
public class EncryptionProcessContext {
    final Cipher cipher;
    final PublicKey theirPublicKey;
    final PrivateKey myPrivateKey;
    byte[] signature;

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private final SecretKey secretKey;



    public EncryptionProcessContext(Cipher cipher, PublicKey theirPublicKey, PrivateKey myPrivateKey, SecretKey secretKey) {
        this.cipher = cipher;
        this.theirPublicKey = theirPublicKey;
        this.myPrivateKey = myPrivateKey;
        this.secretKey = secretKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

}
