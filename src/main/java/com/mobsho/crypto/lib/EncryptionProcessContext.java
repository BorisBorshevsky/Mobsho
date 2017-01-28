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
    Optional<IvParameterSpec> iv;
    byte[] signature;

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    SecretKey secretKey;



    public EncryptionProcessContext(Cipher cipher, PublicKey theirPublicKey, PrivateKey myPrivateKey, SecretKey secretKey, Optional<IvParameterSpec> iv) {
        this.cipher = cipher;
        this.theirPublicKey = theirPublicKey;
        this.myPrivateKey = myPrivateKey;
        this.iv = iv;
        this.secretKey = secretKey;
    }

    public Cipher getCipher() {
        return cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public PublicKey getTheirPublicKey() {
        return theirPublicKey;
    }

    public void setTheirPublicKey(PublicKey theirPublicKey) {
        this.theirPublicKey = theirPublicKey;
    }

    public Key getMyPrivateKey() {
        return myPrivateKey;
    }

    public void setMyPrivateKey(PrivateKey myPrivateKey) {
        this.myPrivateKey = myPrivateKey;
    }

    public Optional<IvParameterSpec> getIv() {
        return iv;
    }

    public void setIv(Optional<IvParameterSpec> iv) {
        this.iv = iv;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }
}
