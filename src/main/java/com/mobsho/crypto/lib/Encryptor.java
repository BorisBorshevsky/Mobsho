package com.mobsho.crypto.lib;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Optional;

/**
 * Created by boris on 1/27/17.
 */
public class Encryptor {
//		this.keyStoreHelper = new KeyStoreHelper(keyStoreFilename, keyStorePassword);

    KeyStoreHelper keyStoreHelper;

    public Encryptor(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }


    static final String DEFAULT_ALGORITHM = "AES/CBC/PKCS5Padding";

    private EncryptionProcessContext initEncryptionOptions(String myPrivateKeyAlias, String theirPublicKeyAlias, Optional<String> cipherProvider, Optional<String> cipherAlgorithm) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);
        PrivateKey myPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);

        final SecretKey aesKey = createKey(Optional.empty());

        Cipher myCipher;
        if (cipherProvider.isPresent()) {
            myCipher = Cipher.getInstance(cipherAlgorithm.orElse(DEFAULT_ALGORITHM), cipherProvider.get());
        } else {
            myCipher = Cipher.getInstance(cipherAlgorithm.orElse(DEFAULT_ALGORITHM));
        }

        if (isIvRequired(cipherAlgorithm.orElse(DEFAULT_ALGORITHM))) {
//            IvParameterSpec iv = createIV(myCipher.getBlockSize(), Optional.empty());
            SecureRandom secRandCipher = SecureRandom.getInstance("SHA1PRNG");
            secRandCipher.setSeed(1024);
            myCipher.init(Cipher.ENCRYPT_MODE, aesKey, secRandCipher);
//            myCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
//            return new EncryptionProcessContext(myCipher, theirPublicKey, myPrivateKey, aesKey, Optional.of(iv));
            return new EncryptionProcessContext(myCipher, theirPublicKey, myPrivateKey, aesKey, Optional.empty());
        } else {
            return new EncryptionProcessContext(myCipher, theirPublicKey, myPrivateKey, aesKey, Optional.empty());
        }

        //Initializes this cipher with the public key from the given certificate and a source of randomness (IV).

    }

    private boolean isIvRequired(String algorithm) {
        return true;
    }

    public EncryptionProcessContext EncryptFile(String fileToEncrypt, OutputStream output, String myPrivateKeyAlias, String theirPublicKeyAlias, Optional<String> cipherProvider, Optional<String> cipherAlgorithm) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        EncryptionProcessContext options = initEncryptionOptions(myPrivateKeyAlias, theirPublicKeyAlias, cipherProvider, cipherAlgorithm);

//        CipherOutputStream encryptedStream = new CipherOutputStream(output, options.cipher);
//        FileInputStream streamToEncrypt = new FileInputStream(fileToEncrypt);

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

    private IvParameterSpec createIV(final int ivSizeBytes, final Optional<SecureRandom> rng) {
        final byte[] iv = new byte[ivSizeBytes];
        final SecureRandom theRNG = rng.orElse(new SecureRandom());
        theRNG.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

}

