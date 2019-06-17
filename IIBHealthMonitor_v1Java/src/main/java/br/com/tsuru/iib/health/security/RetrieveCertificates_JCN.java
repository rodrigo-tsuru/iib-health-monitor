package br.com.tsuru.iib.health.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import com.ibm.broker.config.proxy.BrokerProxy;
import com.ibm.broker.config.proxy.ExecutionGroupProxy;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.javastartparameters.JavaStartParameters;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbJSON;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;

public class RetrieveCertificates_JCN extends MbJavaComputeNode {

	private final static Logger LOGGER = Logger.getLogger(RetrieveCertificates_JCN.class.getName());
	
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
	
	private static int CERTIFICATE_EXPIRATION_INTERVAL = 90;
	
	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		MbOutputTerminal alt = getOutputTerminal("alternate");

		MbMessage inMessage = inAssembly.getMessage();

		// create new empty message
		MbMessage outMessage = new MbMessage();
		MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly,
				outMessage);
		
		Calendar expirationCal = Calendar.getInstance();
		expirationCal.add(Calendar.DATE, CERTIFICATE_EXPIRATION_INTERVAL);
		final Date CHECK_DATE = expirationCal.getTime();
		
		BrokerProxy b = null;
		
		try {
			// optionally copy message headers
			copyMessageHeaders(inMessage, outMessage);
			// ----------------------------------------------------------
			// Add user code below
			b = BrokerProxy.getLocalInstance();
			
			if(b.hasBeenPopulatedByBroker(true)) {
				
			} else {
				throw new RuntimeException("Cannot communicate with local Integration Node");
			}
			
			List<X509Certificate> seList = new ArrayList<X509Certificate>();
			
			//TODO: check IIB's JRE cacerts file
			
			String broker = getBroker().getName();
			
			// @see https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ab60250_.htm
			// Verifies node's keystore and trust stores used by request nodes (ex: HTTPRequest, SOAPRequest)
			String ksFile = b.getRegistryProperty("BrokerRegistry/brokerKeystoreFile");
			String ksPass = b.getRegistryProperty("BrokerRegistry/brokerKeystorePass");
			String ksType = b.getRegistryProperty("BrokerRegistry/brokerKeystoreType");
			
			if(ksFile.isEmpty())
				LOGGER.finest("Broker Keystore is not set");
			else
				seList.addAll(getCertificates(ksFile,ksPass,ksType));
			
			String tsFile = b.getRegistryProperty("BrokerRegistry/brokerTruststoreFile");
			String tsPass = b.getRegistryProperty("BrokerRegistry/brokerTruststorePass");
			String tsType = b.getRegistryProperty("BrokerRegistry/brokerTruststoreType");
			
			if(tsFile.isEmpty())
				LOGGER.finest("Broker Truststore is not set");
			else
				seList.addAll(getCertificates(tsFile,tsPass,tsType));
			
			// Verifies node's keystore and trust stores used by input nodes (ex: HTTPInput, SOAPInput)
			String HTTPS_ksFile = b.getHTTPListenerProperty("HTTPSConnector/keystoreFile");
			String HTTPS_ksPass = b.getHTTPListenerProperty("HTTPSConnector/keystorePass");
			String HTTPS_ksType = b.getHTTPListenerProperty("HTTPSConnector/keystoreType");
			
			if(HTTPS_ksFile.isEmpty())
				LOGGER.finest("Broker HTTPSConnector Keystore is not set");
			else
				seList.addAll(getCertificates(HTTPS_ksFile,HTTPS_ksPass,HTTPS_ksType));
			
			String HTTPS_tsFile = b.getHTTPListenerProperty("HTTPSConnector/truststoreFile");
			String HTTPS_tsPass = b.getHTTPListenerProperty("HTTPSConnector/truststorePass");
			String HTTPS_tsType = b.getHTTPListenerProperty("HTTPSConnector/truststoreType");
			
			if(tsFile.isEmpty())
				LOGGER.finest("Broker Truststore is not set");
			else
				seList.addAll(getCertificates(HTTPS_tsFile,HTTPS_tsPass,HTTPS_tsType));
			
			//TODO: check CRL?
			
			Enumeration<ExecutionGroupProxy> egs = b.getExecutionGroups(null);
			
			while(egs.hasMoreElements()) {
				
				// @see https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ac56640_.htm
				
				// Verifies EG's keystore and trust stores used by request nodes (ex: HTTPRequest, SOAPRequest)
				ExecutionGroupProxy eg = egs.nextElement();
				String egKsFile = eg.getRuntimeProperty("ComIbmJVMManager/keystoreFile");
				String egKsPass = eg.getRuntimeProperty("ComIbmJVMManager/keystorePass");
				String egKsType = eg.getRuntimeProperty("ComIbmJVMManager/keystoreType");
				
				if(egKsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " Keystore is not set");
				else
					seList.addAll(getCertificates(egKsFile,egKsPass,egKsType));
				
				String egTsFile = eg.getRuntimeProperty("ComIbmJVMManager/truststoreFile");
				String egTsPass = eg.getRuntimeProperty("ComIbmJVMManager/truststorePass");
				String egTsType = eg.getRuntimeProperty("ComIbmJVMManager/truststoreType");
				
				
				if(egTsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " Truststore is not set");
				else
					seList.addAll(getCertificates(egTsFile,egTsPass,egTsType));
				
				// Verifies EG's keystore and trust stores used by input nodes (ex: HTTPInput, SOAPInput)
				String egHTTPS_KsFile = eg.getRuntimeProperty("HTTPSConnector/keystoreFile");
				String egHTTPS_KsPass = eg.getRuntimeProperty("HTTPSConnector/keystorePass");
				String egHTTPS_KsType = eg.getRuntimeProperty("HTTPSConnector/keystoreType");
				
				if(egHTTPS_KsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " HTTPSConnector Keystore is not set");
				else
					seList.addAll(getCertificates(egHTTPS_KsFile,egHTTPS_KsPass,egHTTPS_KsType));
				
				String egHTTPS_TsFile = eg.getRuntimeProperty("HTTPSConnector/truststoreFile");
				String egHTTPS_TsPass = eg.getRuntimeProperty("HTTPSConnector/truststorePass");
				String egHTTPS_TsType = eg.getRuntimeProperty("HTTPSConnector/truststoreType");
				
				
				if(egHTTPS_TsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " HTTPSConnector Truststore is not set");
				else
					seList.addAll(getCertificates(egHTTPS_TsFile,egHTTPS_TsPass,egHTTPS_TsType));
				
			}
			
			// Generate result message
			
			MbElement data = outMessage.getRootElement()
			.createElementAsLastChild(MbJSON.ROOT_ELEMENT_NAME)
			.createElementAsLastChild(MbElement.TYPE_NAME,"Data",null);
			
			MbElement certs = data
					.createElementAsLastChild(MbJSON.ARRAY,"certs",null);
				
			for (X509Certificate cert : seList) {
				MbElement item = certs
					.createElementAsLastChild(MbJSON.OBJECT,MbJSON.ARRAY_ITEM_NAME,null);
				
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"version",cert.getVersion());
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"serial",cert.getSerialNumber().toString());
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"signatureAlgorithmID",cert.getSigAlgName());
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"issuerName",cert.getIssuerDN().getName());
				MbElement val = item.createElementAsLastChild(MbJSON.OBJECT,"validityPeriod",null);
				val.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"notBefore",sdf.format(cert.getNotBefore()));
				val.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"notAfter",sdf.format(cert.getNotAfter()));
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"fingerprint",getThumbprint(cert));
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"subjectName",cert.getSubjectDN().getName());
				
				
			}
			out.propagate(outAssembly);
			// End of user code
			// ----------------------------------------------------------
		} catch (MbException e) {
			// Re-throw to allow Broker handling of MbException
			throw e;
		} catch (RuntimeException e) {
			// Re-throw to allow Broker handling of RuntimeException
			throw e;
		} catch (Exception e) {
			// Consider replacing Exception with type(s) thrown by user code
			// Example handling ensures all exceptions are re-thrown to be handled in the flow
			throw new MbUserException(this, "evaluate()", "", "", e.toString(),
					null);
		} finally{
			outMessage.clearMessage(true);
		}
		// The following should only be changed
		// if not propagating message to the 'out' terminal
		
	}
	
	private static String getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        return digestHex.toLowerCase();
    }
	
	private List<X509Certificate> getCertificates(String ksFile, String ksPass, String ksType) {
		
		List<X509Certificate> list = new ArrayList<X509Certificate>();
		
		KeyStore ks;
		try (FileInputStream fis = new java.io.FileInputStream(ksFile)){
			
			if(ksType==null || ksType.isEmpty()) {
				ks = KeyStore.getInstance(KeyStore.getDefaultType());
			} else {
				ks = KeyStore.getInstance(ksType);
			}
			char[] password = null;
			
			if(ksPass.contains("::")) {
				String[] ksPassSecurityAlias = ksPass.split("::");
				String credentials[] = JavaStartParameters.getResourceUserAndPassword(ksPassSecurityAlias[0] +"::", "", ksPassSecurityAlias[1]);
				password = credentials[1].toCharArray();
			} else {
				password = ksPass.toCharArray();
			}
			
			ks.load(fis, password);
	        Enumeration<String> enumeration = ks.aliases();
	        while(enumeration.hasMoreElements()) {
	            String alias = enumeration.nextElement();

	            Certificate[] chain = ks.getCertificateChain(alias);
	            if (chain!=null){
		            for(Certificate cert : chain) {
		            	X509Certificate x509cert = (X509Certificate) cert;
		            	list.add(x509cert);
		            }
	            } else {
	            	X509Certificate x509cert = (X509Certificate) ks.getCertificate(alias);
	            	list.add(x509cert);
	            }
	        }
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			LOGGER.severe(e.getMessage());
			} catch (FileNotFoundException e1) {
			LOGGER.severe(e1.getMessage());
			} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			LOGGER.severe(e.getMessage());
			} catch (CertificateException e) {
			e.printStackTrace();
			LOGGER.severe(e.getMessage());
			} catch (IOException e) {
			e.printStackTrace();
			LOGGER.severe(e.getMessage());
			} catch (Exception e) {
			e.printStackTrace();
			LOGGER.severe(e.getMessage());
		}
		
		return list;
		
	}
	public void copyMessageHeaders(MbMessage inMessage, MbMessage outMessage)
			throws MbException {
		MbElement outRoot = outMessage.getRootElement();

		// iterate though the headers starting with the first child of the root
		// element
		MbElement header = inMessage.getRootElement().getFirstChild();
		while (header != null && header.getNextSibling() != null) // stop before
																	// the last
																	// child
																	// (body)
		{
			// copy the header and add it to the out message
			outRoot.addAsLastChild(header.copy());
			// move along to next header
			header = header.getNextSibling();
		}
	}
}
