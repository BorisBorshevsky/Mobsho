package com.mobsho.crypto.lib;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreHelper {

    private KeyStore keystore;
    private char[] pwd;
    private String keyStoreFilename;

    public KeyStoreHelper(String keyStoreFilename, String ksPassword) {
        this.pwd = ksPassword.toCharArray();
        this.keyStoreFilename = keyStoreFilename;
    }

    private void initKeystore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream fIn = new FileInputStream(keyStoreFilename);
        this.keystore = KeyStore.getInstance("JKS");
        this.keystore.load(fIn, this.pwd);
    }

    /**
     * Returns the key in its primary encoding format, or null if the certificate associated with the given alias doesn't exist.
     */
    public PublicKey getPublicKey(String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (this.keystore == null) {
            initKeystore();
        }

        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }


    /**
     * Returns the key in its primary encoding format, or null if the certificate associated with the given alias doesn't exist, or wrong password.
     */
    public Key getPrivateKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        if (this.keystore == null) {
            initKeystore();
        }
        return this.keystore.getKey(alias, this.pwd);
    }


}
