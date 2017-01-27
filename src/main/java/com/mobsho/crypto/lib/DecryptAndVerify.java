package com.mobsho.crypto.lib;

import java.security.Key;
import java.security.PublicKey;

public class DecryptAndVerify {

	ChipherImpl ChiperHandler;
	DigitalSignatureImpl digitalSignatureHandler;
	KeyStoreHelper keyStoreHelper;


	public DecryptAndVerify(String keyStoreFilename, String keyStorePassword) {
		this.ChiperHandler = new ChipherImpl();
		this.digitalSignatureHandler = new DigitalSignatureImpl();
		this.keyStoreHelper = new KeyStoreHelper(keyStoreFilename, keyStorePassword);
	}
	

	/*public void DecryptAndVerifyFile(String keyAlias, String keyPassword, String encryptedDataFileName, String configFileName, String encryptedKeyFileName)*/
	
	public int DecryptAndVerifyFile(String myPrivateKeyAlias, String myPrivateKeyPassword, String theirPublicKeyAlias,  String encryptedFileName) {
		//Names of files to be used for decryption and data verification
		String decryptedData = "data.dec";
		String configurationFile = "configuration.xml";
		//Load pair of Keys
		//QAQA - Must get passwords from user.
		try {
			//Load keys:
			//Load my asymetric private key for decryption
			Key myAsymetricPrivateKey = keyStoreHelper.getPrivateKey(myPrivateKeyAlias);
			//Load the other side's asymetric public key for digital verifcation
			PublicKey theirPublicKey = keyStoreHelper.getPublicKey(theirPublicKeyAlias);
			
			//Extract parameters from the XML configuration file
        	XMLhandler xmlhandler = new XMLhandler(null, null, null);
        	xmlhandler.parseConfigurationFile(configurationFile);
        	byte[] encodedAlgorithmParametres = xmlhandler.getAlgorithmParameters();
        	byte[] encryptedPrivateKey = xmlhandler.getEncryptedPrivateKey();
        	byte[] digitalSignature = xmlhandler.getDigitalSignature();
        	
			//Decrypt/extract private key
        	int flag = ChiperHandler.decryptPrivateKey(myAsymetricPrivateKey, encryptedPrivateKey);
			if(flag==0){
				//Decrypt file "encryptedFileName" content and save in "decryptedData"
				this.ChiperHandler.decryptFile(encryptedFileName, decryptedData, encodedAlgorithmParametres);
			}else {
				System.out.println("DecryptAndVerifyFile: Error. Couldn't decrypt.");
				return -1;
			}
			
			//Verify file by signature
			digitalSignatureHandler.verifyData(digitalSignature, decryptedData, theirPublicKey);
			
			
			return 0;
			
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		
		//Failure
		return -1;
	
	}


}
