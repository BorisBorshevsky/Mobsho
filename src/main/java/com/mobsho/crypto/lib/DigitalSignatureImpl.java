package com.mobsho.crypto.lib;

import java.io.*;
import java.security.*;


public class DigitalSignatureImpl {
	
	private String signAlgorithm;
	private String signProvider;
	private Key priv;
	
	//Default constructor
	public DigitalSignatureImpl(){
		this.signAlgorithm = "SHA1withRSA";
		this.signProvider = null; /*Using default provider*/
	}
	
	//Setters
	
	public void setSignatureAlgorithm(String signAlgorithm) {
		this.signAlgorithm = signAlgorithm;
	}
	
	public void setSignatureProvider(String signProvider) {
		this.signProvider = signProvider;
	}

	/**
	 * Input: inputFile = input file name to be signed, myPrivateAsymetricKey = sender's asymetric private signing key  
	 * */
    public byte[] signData(String inputFile, Key myPrivateAsymetricKey) {
    	
    	this.priv = myPrivateAsymetricKey;
    	
        /* Generate a DSA signature */
        try {
        	Signature sig;
        	//Get a Signature Object
        	if(this.signProvider!=null){
        		sig = Signature.getInstance(this.signAlgorithm, this.signProvider);
        	}else{
        		sig = Signature.getInstance(this.signAlgorithm);
        	}
        	
        	//Initialize the Signature Object
        	sig.initSign((PrivateKey)priv);
        	
        	//Supply the Signature Object the Data to Be Signed
        	FileInputStream fis = new FileInputStream(inputFile);
        	BufferedInputStream bufin = new BufferedInputStream(fis);
        	byte[] buffer = new byte[1024];
        	int len;
        	while ((len = bufin.read(buffer)) >= 0) {
        		sig.update(buffer, 0, len);
        	};
        	bufin.close();
        	
        	//Generate the Signature
        	byte[] realSig = sig.sign();
        	return realSig;
        	
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
        
        return null;
    }


	/**
	 * Input: inputFile = input file name to be signed, myPrivateAsymetricKey = sender's asymetric private signing key  
	 * */
    public void verifyData(byte[] signature, String inputFile, PublicKey theirPublicAsymetricKey){
    	 	
    	try {

    		//Initialize the Signature Object for Verification
    		Signature sig;
        	//Get a Signature Object
        	if(this.signProvider!=null){
        		sig = Signature.getInstance(this.signAlgorithm, this.signProvider);
        	}else{
        		sig = Signature.getInstance(this.signAlgorithm);
        	}
    		sig.initVerify(theirPublicAsymetricKey);
    		
    		//Verify the Signature
    		//Supply the Signature Object With the Data to be Verified 
    		FileInputStream datafis = new FileInputStream(inputFile);
    		BufferedInputStream bufin = new BufferedInputStream(datafis);

    		byte[] buffer = new byte[1024];
    		int len;
    		while (bufin.available() != 0) {
    		    len = bufin.read(buffer);
    		    sig.update(buffer, 0, len);
    		};

    		bufin.close();
    		datafis.close();
    		
    		//Verify the Signature
    		boolean verifies = sig.verify(signature);
    		System.out.println("******************************");
    		if(verifies == true){
        		System.out.println("Signature is valid! :)");
    		}else{
    			System.out.println("Signature is NOT valid NOT valid NOT valid");
    		}
    		System.out.println("******************************");
    		
            } catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            }
    	
    }
}
