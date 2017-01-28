package com.mobsho.crypto.lib;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.IOException;



public class ConfigurationManager {

    private static final String ENCRYPTION = "Encryption";
    private static final String ALG_PARAMS = "algParams";
    private static final String ENC_PRIVATE_KEY = "encPrivateKey";
    private static final String SIG = "Sig";
    private static final String CONF = "Conf";
    private byte[] encodedAlgorithmParameters;
    private byte[] encryptedPrivateKey;
    private byte[] digitalSignature;

    private static final String CONFIGURATION_XML = "conf.xml";

    public ConfigurationManager() {
    }

    public ConfigurationManager(byte[] encodedAlgorithmParameters, byte[] encryptedPrivateKey, byte[] signature) {
        this.encodedAlgorithmParameters = encodedAlgorithmParameters;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.digitalSignature = signature;
    }

    //getters
    public byte[] getAlgorithmParameters() {
        return this.encodedAlgorithmParameters;
    }

    public byte[] getEncryptedSecretKey() {
        return this.encryptedPrivateKey;
    }

    public byte[] getDigitalSignature() {
        return this.digitalSignature;
    }

    public void dumpToFile() throws ParserConfigurationException, TransformerException {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement(CONF);
        doc.appendChild(rootElement);

        // staff elements
        Element staff = doc.createElement(ENCRYPTION);
        rootElement.appendChild(staff);

        // Encrypted password element
        Element AlgorithmParametersElement = doc.createElement(ALG_PARAMS);
        String base64StringAP = DatatypeConverter.printBase64Binary(this.encodedAlgorithmParameters);
        AlgorithmParametersElement.appendChild(doc.createTextNode(base64StringAP));
        staff.appendChild(AlgorithmParametersElement);

        // Encrypted signature element
        Element signatureElement = doc.createElement(SIG);
        String base64StringS = DatatypeConverter.printBase64Binary(this.digitalSignature);
        signatureElement.appendChild(doc.createTextNode(base64StringS));
        staff.appendChild(signatureElement);

        // Encrypted password element
        Element EncryptedPasswordElement = doc.createElement(ENC_PRIVATE_KEY);
        String base64StringEPK = DatatypeConverter.printBase64Binary(this.encryptedPrivateKey);
        EncryptedPasswordElement.appendChild(doc.createTextNode(base64StringEPK));
        staff.appendChild(EncryptedPasswordElement);

        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(CONFIGURATION_XML));

        transformer.transform(source, result);
    }


    public ConfigurationManager parseFile() throws ParserConfigurationException, IOException, SAXException {
        return parseFile(CONFIGURATION_XML);
    }

    public ConfigurationManager parseFile(String fileName) throws ParserConfigurationException, IOException, SAXException {
        File stocks = new File(fileName);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(stocks);
        doc.getDocumentElement().normalize();


        NodeList nodes = doc.getElementsByTagName(CONF);
        Node node = nodes.item(0);
        Element element = (Element) node;

        String base64StringEAP = getValue(ALG_PARAMS, element);
        String base64StringEPK = getValue(ENC_PRIVATE_KEY, element);
        String base64StringDS = getValue(SIG, element);

        this.encodedAlgorithmParameters = DatatypeConverter.parseBase64Binary(base64StringEAP);
        this.encryptedPrivateKey = DatatypeConverter.parseBase64Binary(base64StringEPK);
        this.digitalSignature = DatatypeConverter.parseBase64Binary(base64StringDS);

        return this;
    }

    private static String getValue(String tag, Element element) {
        NodeList nodes = element.getElementsByTagName(tag).item(0).getChildNodes();
        Node node = nodes.item(0);
        return node.getNodeValue();
    }

}
