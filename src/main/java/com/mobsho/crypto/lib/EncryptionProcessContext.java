package com.mobsho.crypto.lib;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Optional;

/**
 * Created by boris on 1/28/17.
 */
public class EncryptionProcessContext {
    Cipher cipher;
    PublicKey theirPublicKey;
    PrivateKey myPrivateKey;
    private Optional<IvParameterSpec> iv;
    byte[] signature;

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private SecretKey secretKey;



    public EncryptionProcessContext(Cipher cipher, PublicKey theirPublicKey, PrivateKey myPrivateKey, SecretKey secretKey, Optional<IvParameterSpec> iv) {
        this.cipher = cipher;
        this.theirPublicKey = theirPublicKey;
        this.myPrivateKey = myPrivateKey;
        this.iv = iv;
        this.secretKey = secretKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

}
