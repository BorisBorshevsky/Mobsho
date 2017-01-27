package com.mobsho.crypto.lib;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Key;
import java.security.SecureRandom;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class ChipherImpl {
	
	private KeyGenerator kg;
	private SecretKey sKey;
	private String ChipherAlgorithm;
	private String ChipherProvider;
	
	
	//Constructor
	public ChipherImpl(){
		this.ChipherAlgorithm = "AES/CBC/PKCS5Padding";
		this.ChipherProvider = null; /*Using default provider*/
	}
	
	
	/**
	 * The provided setters enable easy replacement of chipher algorithm and provider.
	 * Defaults are: algorithm: "AES/CBC/PKCS5Padding", provider: default provider
	 * */
	//Setters
	public void setChipherAlgorithm(String ChipherAlgorithm){
		this.ChipherAlgorithm = ChipherAlgorithm;
	}
	
	public void setChipherProvider(String ChipherProvider){
		this.ChipherProvider = ChipherProvider;
	}
	
	//Getters
	
	public String getChipherAlgorithm(){
		return this.ChipherAlgorithm;
	}
	
	public String getChipherProvider(){
		return this.ChipherProvider;
	}

	
	//Generate a private key ("SecretKey sKey") for encryption 
	private void generatePrivateKey(){
		
		try {
			//Generate source of randomness
			SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
			secRand.setSeed(1024);
			
			//Generate key randomly
			this.kg = KeyGenerator.getInstance("AES");  //QAQA - need to specify a provider
			this.kg.init(secRand);
			sKey = kg.generateKey(); 

		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
	
	//Encrypts the private key
	public byte[] encryptPrivateKey(PublicKey pubKey){
		
		Cipher c1;
		try {
			//Encrypt the private key using the other side public key
			c1 = Cipher.getInstance("RSA");
			byte[] encodedKey = sKey.getEncoded();
			c1.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] encryptedKey = c1.doFinal(encodedKey);
			
			System.out.println("!!!!!!!!!!!!!!!!!!!! encryptedKey = " + encryptedKey);
			System.out.println("encryptPrivateKey: PK is: " + sKey.toString());
			System.out.println("encryptPrivateKey: Algorithm is: " +sKey.getAlgorithm());
			System.out.println("encryptPrivateKey: getEncoded is: " + sKey.getEncoded().toString());
			
			return encryptedKey;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	
	/** Extracts a private key ("SecretKey sKey") for decryption given a configuration file
	 * 
	 * @param myPrivateAsymetricKey
	 * @param encryptedKey
	 * @return 0 on success, -1 on failure
	 */
	public int decryptPrivateKey(Key myPrivateAsymetricKey, byte[] encryptedKey){
		
		Cipher c1;

		try {
			
			//Decrypt the private key using the other side public key
			c1 = Cipher.getInstance("RSA");
			c1.init(Cipher.DECRYPT_MODE, myPrivateAsymetricKey);
			byte[] decryptedKey = c1.doFinal(encryptedKey);
						
			SecretKeySpec secret = new SecretKeySpec(decryptedKey, "AES");
			this.sKey = secret;
			
			//algParams = AlgorithmParameters.getInstance("RSA");
			/*Cipher myCipher = Cipher.getInstance("RSA");
			myCipher.init(Cipher.DECRYPT_MODE, myPrivateAsymetricKey);
			FileInputStream fis = new FileInputStream(encryptedKeyFileName);
			CipherInputStream cis = new CipherInputStream(fis, myCipher);
			
			CipherInputStream cis = new CipherInputStream(is, c);
			
			byte[] key = new byte[16];  
			int i = cis.read(key);
			
			//write loop
			while (i != -1){
				i = cis.read(key); 
			}
			
			//Close resources
			fis.close();
			cis.close();
			
			SecretKeySpec secret = new SecretKeySpec(key, "AES");
			System.out.println("Secret.getEncoded = " + secret.getEncoded());
			this.sKey = secret;*/
						
			return 0;
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Failure
		return -1;		
		
	}
	
	
	/**
	 * Encrypts a file.
	 * Input: path of file to encrypt, path to encrypted output file
	 * Output: on success returns byte[] algParams, on failure returns null
	 * */
	public byte[] encryptFile(String inputFile) throws IOException{
		FileInputStream fis;
		FileOutputStream fos;
		CipherInputStream cis;
		Cipher myCipher;
				
		try {
			//Generate the private key used for encryption
			this.generatePrivateKey();
			
			//Create a source of randomness for the initialization of the Cipher object
			SecureRandom secRandCipher = SecureRandom.getInstance("SHA1PRNG");
			secRandCipher.setSeed(1024);
			
			//Create Cipher object using the AES algorithm in CBC mode as default (ChipherImpl setters are used to change algorithm and provider)
			if(this.ChipherProvider == null){
				myCipher = Cipher.getInstance(this.ChipherAlgorithm);
			}else{
				myCipher = Cipher.getInstance(this.ChipherAlgorithm, this.ChipherProvider);
			}
	
			//Initializes this cipher with the public key from the given certificate and a source of randomness (IV).
			myCipher.init(Cipher.ENCRYPT_MODE, this.sKey, secRandCipher);

			//Open streams to encrypt data
			fis = new FileInputStream(inputFile);
			fos = new FileOutputStream("data.enc");
			cis = new CipherInputStream(fis, myCipher);
			
			byte[] buffer = new byte[8];
			int i = cis.read(buffer);
			
			//write loop
			while (i != -1){
				fos.write(buffer, 0, i);
				i = cis.read(buffer); 
			}
			
			//Close resources
			fis.close();
			fos.close();
			cis.close();
			
			// Get algorithm parameters encoding
			AlgorithmParameters algParams = myCipher.getParameters();
			byte[] encodedAlgParams = algParams.getEncoded();

			return  encodedAlgParams;

		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}  //Algorithm/mode/padding; Use getInstance with 2 args - 2nd for provider
		//Initialize the cipher object - encryption mode
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
				
	}
	
	
	/**
	 * Decrypts a file.
	 * Input: path of file to be decrypted, path to decrypted output file
	 * Output: QAQA - MAYBE need to return algParams?
	 * */
	public int decryptFile(String encryptedFile, String decryptedOutputFile, byte[] encodedAlgParams) throws IOException{
		
		FileInputStream fis;
		FileOutputStream fos;
		CipherInputStream cis;
		AlgorithmParameters algParams;
		Cipher myCipher;
				
		try {
			
			algParams = AlgorithmParameters.getInstance("AES");
			// initialize with parameter encoding from above
			algParams.init(encodedAlgParams);
			myCipher = Cipher.getInstance(this.ChipherAlgorithm);
			myCipher.init(Cipher.DECRYPT_MODE, this.sKey, algParams);

			fis = new FileInputStream(encryptedFile);
			fos = new FileOutputStream(decryptedOutputFile);
			cis = new CipherInputStream(fis, myCipher);
			
			byte[] buffer = new byte[8];
			int i = cis.read(buffer);
			
			//write loop
			while (i != -1){
				fos.write(buffer, 0, i);
				i = cis.read(buffer); 
			}
			
			//Close resources
			fis.close();
			fos.close();
			cis.close();
			
			return 0;  

		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}  //Algorithm/mode/padding; Use getInstance with 2 args - 2nd for provider
		//Initialize the cipher object - encryption mode
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return -1;
				
	}
	
	
	
}
