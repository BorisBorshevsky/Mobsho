package com.mobsho.crypto.lib;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Created by boris on 1/27/17.
 */
public class Encryptor {
//		this.keyStoreHelper = new KeyStoreHelper(keyStoreFilename, keyStorePassword);

    KeyStoreHelper keyStoreHelper;

    public Encryptor(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }

    public void Encrypt(String fileToEncrypt, String myPrivateKeyAlias, String theirPublicKeyAlias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        //Load the other side's  public key
        PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);
        Key myAsymetricPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);


        FileInputStream fis = new FileInputStream(fileToEncrypt);
        FileOutputStream fos = new FileOutputStream("data.enc");
//        CipherInputStream cis = new CipherInputStream(fis, myCipher);
//        CipherOutputStream cos = new CipherOutputStream(fos, )
    }

//    private Cipher getCipher(){
//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//        keyGen.init(256); // for example
//        SecretKey secretKey = keyGen.generateKey();
//    }

    public void Sign() {

    }

}

