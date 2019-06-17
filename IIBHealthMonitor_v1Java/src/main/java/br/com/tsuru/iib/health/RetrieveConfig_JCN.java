package br.com.tsuru.iib.health;

import java.net.InetAddress;
import java.text.SimpleDateFormat;

import com.ibm.broker.config.proxy.BrokerProxy;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbJSON;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;


public class RetrieveConfig_JCN extends MbJavaComputeNode {
	
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");

	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		MbOutputTerminal alt = getOutputTerminal("alternate");

		MbMessage inMessage = inAssembly.getMessage();

		// create new empty message
		MbMessage outMessage = new MbMessage();
		MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly,
				outMessage);
		
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
			MbElement data = outMessage.getRootElement()
					.createElementAsLastChild(MbJSON.ROOT_ELEMENT_NAME)
					.createElementAsLastChild(MbElement.TYPE_NAME,"Data",null);
					
			MbElement info = data
					.createElementAsLastChild(MbJSON.OBJECT,"info",null);
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"hostname",InetAddress.getLocalHost().getHostName());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"os",b.getBrokerOSName());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibVersion",b.getBrokerLongVersion());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibArch",b.getBrokerOSArch());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibMQenabled",!b.getQueueManagerName().isEmpty());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibLastUpdateTime",sdf.format(b.getTimeOfLastUpdate().getTime()));
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibJREVersion",System.getProperty("java.fullversion").toString());
			info.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"iibJRETZDataVersion",java.time.zone.ZoneRulesProvider.getVersions("America/Sao_Paulo").lastEntry().getKey());
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
		} finally {
			outMessage.clearMessage(true);
		}
		// The following should only be changed
		// if not propagating message to the 'out' terminal
		
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
