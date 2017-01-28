package com.mobsho.crypto.lib;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CreateKeyAndIVForAES_CBC {

    public static SecretKey createKey(final String algorithm, final int keysize, final Optional<Provider> provider, final Optional<SecureRandom> rng) throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator;
        if (provider.isPresent()) {
            keyGenerator = KeyGenerator.getInstance(algorithm, provider.get());
        } else {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        }

        if (rng.isPresent()) {
            keyGenerator.init(keysize, rng.get());
        } else {
            // not really needed for the Sun provider which handles null OK
            keyGenerator.init(keysize);
        }

        return keyGenerator.generateKey();
    }

    public static IvParameterSpec createIV(final int ivSizeBytes, final Optional<SecureRandom> rng) {
        final byte[] iv = new byte[ivSizeBytes];
        final SecureRandom theRNG = rng.orElse(new SecureRandom());
        theRNG.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static IvParameterSpec readIV(final int ivSizeBytes, final InputStream is) throws IOException {
        final byte[] iv = new byte[ivSizeBytes];
        int offset = 0;
        while (offset < ivSizeBytes) {
            final int read = is.read(iv, offset, ivSizeBytes - offset);
            if (read == -1) {
                throw new IOException("Too few bytes for IV in input stream");
            }
            offset += read;
        }
        return new IvParameterSpec(iv);
    }

    public static void main(String[] args) throws Exception {
        final SecureRandom rng = new SecureRandom();
        // you somehow need to distribute this key
        final SecretKey aesKey = createKey("AES", 128, Optional.empty(), Optional.of(rng));
        final byte[] plaintext = "BORIS AAAAAAA".getBytes(UTF_8);

        final byte[] ciphertext;

        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            final Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
            final IvParameterSpec ivForCBC = createIV(aesCBC.getBlockSize(), Optional.of(rng));
            aesCBC.init(Cipher.ENCRYPT_MODE, aesKey, ivForCBC);
            baos.write(ivForCBC.getIV());

            try (final CipherOutputStream cos = new CipherOutputStream(baos, aesCBC)) {
                cos.write(plaintext);
            }

            ciphertext = baos.toByteArray();
        }

        final byte[] decrypted;

        {
            final ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);

            final Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
            final IvParameterSpec ivForCBC = readIV(aesCBC.getBlockSize(), bais);
            aesCBC.init(Cipher.DECRYPT_MODE, aesKey, ivForCBC);

            final byte[] buf = new byte[1_024];
            try (final CipherInputStream cis = new CipherInputStream(bais, aesCBC);
                 final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                int read;
                while ((read = cis.read(buf)) != -1) {
                    baos.write(buf, 0, read);
                }
                decrypted = baos.toByteArray();
            }
        }

        System.out.println(new String(decrypted, UTF_8));
    }

    public static void main2(String[] args) throws InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException {
        try {
            String message = "This string contains a secret message.";
            System.out.println("Plaintext: " + message + "\n");

            // generate a key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);  // To use 256 bit keys, you need the "unlimited strength" encryption policy files from Sun.
            byte[] key = keygen.generateKey().getEncoded();
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            // build the initialization vector (randomly).
            SecureRandom random = new SecureRandom();
            byte iv[] = new byte[16];//generate random 16 byte IV AES is always 16bytes
            random.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // initialize the cipher for encrypt mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);

            System.out.println("Key: " + new String(key, "utf-8") + " This is important when decrypting");
            System.out.println("IV: " + new String(iv, "utf-8") + " This is important when decrypting");
            System.out.println();

            // encrypt the message
            byte[] encrypted = cipher.doFinal(message.getBytes());
            System.out.println("Ciphertext: " + asHex(encrypted) + "\n");

            // reinitialize the cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);

            // decrypt the message
            byte[] decrypted = cipher.doFinal(encrypted);
            System.out.println("Plaintext: " + new String(decrypted) + "\n");
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Turns array of bytes into string
     *
     * @param buf Array of bytes to convert to hex string
     * @return Generated hex string
     */
    public static String asHex(byte buf[]) {
        StringBuilder strbuf = new StringBuilder(buf.length * 2);
        int i;
        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }
}