package com.mobsho.crypto.lib;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Optional;

/**
 * Created by boris on 1/27/17.
 */
class Encryptor {

    private final KeyStoreHelper keyStoreHelper;

    public Encryptor(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }


    private static final String DEFAULT_ALGORITHM = "AES/CBC/PKCS5Padding";

    private EncryptionProcessContext initEncryptionOptions(String myPrivateKeyAlias, String theirPublicKeyAlias, Optional<String> cipherProvider, Optional<String> cipherAlgorithm) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);
        PrivateKey myPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);

        final SecretKey aesKey = createKey(Optional.empty());

        Cipher myCipher;
        if (cipherProvider.isPresent()) {
            myCipher = Cipher.getInstance(cipherAlgorithm.orElse(DEFAULT_ALGORITHM), cipherProvider.get());
        } else {
            myCipher = Cipher.getInstance(cipherAlgorithm.orElse(DEFAULT_ALGORITHM));
        }

        SecureRandom secRandCipher = SecureRandom.getInstance("SHA1PRNG");
        secRandCipher.setSeed(1024);
        myCipher.init(Cipher.ENCRYPT_MODE, aesKey, secRandCipher);
        return new EncryptionProcessContext(myCipher, theirPublicKey, myPrivateKey, aesKey);
    }


    public EncryptionProcessContext EncryptFile(String fileToEncrypt, OutputStream output, String myPrivateKeyAlias, String theirPublicKeyAlias, Optional<String> cipherProvider, Optional<String> cipherAlgorithm) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException {
        EncryptionProcessContext options = initEncryptionOptions(myPrivateKeyAlias, theirPublicKeyAlias, cipherProvider, cipherAlgorithm);

        FileInputStream streamToEncrypt = new FileInputStream(fileToEncrypt);
        CipherInputStream cipherInputStream = new CipherInputStream(streamToEncrypt, options.cipher);

        //write loop
        final byte[] buf = new byte[8];
        int read;
        while ((read = cipherInputStream.read(buf)) != -1) {
            output.write(buf, 0, read);
        }

        streamToEncrypt.close();
        output.close();


        return options;
    }

    private SecretKey createKey(final Optional<Provider> provider) throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator;
        if (provider.isPresent()) {
            keyGenerator = KeyGenerator.getInstance("AES", provider.get());
        } else {
            keyGenerator = KeyGenerator.getInstance("AES");
        }

        SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
        secRand.setSeed(1024);

        keyGenerator.init(secRand);

        return keyGenerator.generateKey();
    }

}

