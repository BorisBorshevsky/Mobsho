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

public class KeyStoreHandler {

    private KeyStore keystore;


    public KeyStoreHandler(String keystoreFilename, String ksPassword) {
        FileInputStream fIn;

        //Load keystore
        try {
            fIn = new FileInputStream(keystoreFilename);
            this.keystore = KeyStore.getInstance("JKS");
            this.keystore.load(fIn, ksPassword.toCharArray());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * Returns the key in its primary encoding format, or null if the certificate associated with the given alias doesn't exist.
     */
    public PublicKey getPublicKey(String alias) throws KeyStoreException {
        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }


    /**
     * Returns the key in its primary encoding format, or null if the certificate associated with the given alias doesn't exist, or wrong password.
     */
    public Key getPrivateKey(String alias, String password) {
        char[] passwordArray = password.toCharArray();
        try {
            if (this.keystore.containsAlias(alias)) {
                return this.keystore.getKey(alias, passwordArray);
            }
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        System.out.println("Alias is not found!");

        return null;
    }


}
