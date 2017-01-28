package com.mobsho.crypto.lib;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

class KeyStoreHelper {

    private KeyStore keystore;
    private final char[] pwd;
    private final String keyStoreFilename;

    public KeyStoreHelper(String keyStoreFilename, String ksPassword) {
        this.pwd = ksPassword.toCharArray();
        this.keyStoreFilename = keyStoreFilename;
    }

    private void initKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream fIn = new FileInputStream(keyStoreFilename);
        this.keystore = KeyStore.getInstance("JKS");
        this.keystore.load(fIn, this.pwd);
    }

    public PublicKey getPublicKey(String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (this.keystore == null) {
            initKeyStore();
        }

        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }


    public PrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        if (this.keystore == null) {
            initKeyStore();
        }
        return (PrivateKey) this.keystore.getKey(alias, this.pwd);
    }


}
