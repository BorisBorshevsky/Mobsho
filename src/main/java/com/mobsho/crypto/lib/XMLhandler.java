package com.mobsho.crypto.lib;

import java.io.File;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class XMLhandler {
	
	private byte[] encodedAlgorithmParametres;
	private byte[] encryptedPrivateKey;
	private byte[] digitalSignature;
	
	public XMLhandler(byte[] AencodedAlgorithmParametres, byte[] AencryptedPrivateKey, byte[] Asignature) {
		this.encodedAlgorithmParametres = AencodedAlgorithmParametres;
		this.encryptedPrivateKey = AencryptedPrivateKey;
		this.digitalSignature = Asignature;
	}

	//getters
	public byte[] getAlgorithmParameters(){
		return this.encodedAlgorithmParametres;
	}
	
	public byte[] getEncryptedPrivateKey(){
		return this.encryptedPrivateKey;
	}
	
	public byte[] getDigitalSignature(){
		return this.digitalSignature;
	}

	public int createConfigurationFile() {
		try {
 
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
	 
			// root elements
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("Configuration");
			doc.appendChild(rootElement);
	 
			// staff elements
			Element staff = doc.createElement("Encryption");
			rootElement.appendChild(staff);
	 
			// Encrypted password element
			Element AlgorithmParametresElement = doc.createElement("encodedAlgorithmParametres");
			String base64StringAP = DatatypeConverter.printBase64Binary(this.encodedAlgorithmParametres);
			AlgorithmParametresElement.appendChild(doc.createTextNode(base64StringAP));
			staff.appendChild(AlgorithmParametresElement);
			
			// Encrypted password element
			Element EncryptedPasswordElement = doc.createElement("encryptedPrivateKey");
			String base64StringEPK = DatatypeConverter.printBase64Binary(this.encryptedPrivateKey);
			EncryptedPasswordElement.appendChild(doc.createTextNode(base64StringEPK));
			staff.appendChild(EncryptedPasswordElement);
			
			// Encrypted signature element
			Element signatureElement = doc.createElement("signature");
			String base64StringS = DatatypeConverter.printBase64Binary(this.digitalSignature);
			signatureElement.appendChild(doc.createTextNode(base64StringS));
			staff.appendChild(signatureElement);
	 
			// write the content into xml file
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("configuration.xml"));
	
			transformer.transform(source, result);
	 
		  }catch (ParserConfigurationException pce){
			  pce.printStackTrace();
		  }catch (TransformerException tfe){
			  tfe.printStackTrace();
		  }
		  
		  return 0;
		}
	
	
	public int parseConfigurationFile(String fileName){
		try {
			
			File stocks = new File(fileName);
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(stocks);
			doc.getDocumentElement().normalize();
	
			
			NodeList nodes = doc.getElementsByTagName("Configuration");
			Node node = nodes.item(0);
			Element element = (Element) node;
			
			String base64StringEAP = new String(getValue("encodedAlgorithmParametres", element));
			String base64StringEPK = new String(getValue("encryptedPrivateKey", element));
			String base64StringDS = new String(getValue("signature", element));
			
			this.encodedAlgorithmParametres = DatatypeConverter.parseBase64Binary(base64StringEAP);
			this.encryptedPrivateKey = DatatypeConverter.parseBase64Binary(base64StringEPK);
			this.digitalSignature = DatatypeConverter.parseBase64Binary(base64StringDS);
			
			return 0;
	
			}catch(Exception ex) {
				ex.printStackTrace();
			}
			
		//Failure
		return -1;
		
	}
	
	
	private static String getValue(String tag, Element element) {
		
		NodeList nodes = element.getElementsByTagName(tag).item(0).getChildNodes();
		Node node = (Node) nodes.item(0);
		return node.getNodeValue();
	}
	
}
