/**
 * Copyright (C) 2011-2015 Thales Services SAS.
 *
 * This file is part of AuthZForce.
 *
 * AuthZForce is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthZForce is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthZForce.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.thalesgroup.authzforce.core.test.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AssociatedAdvice;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Obligations;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Request;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.sun.xacml.BasicEvaluationCtx;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ParsingException;
import com.sun.xacml.UnknownIdentifierException;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.support.finder.StaticPolicyFinderModule;
import com.thalesgroup.authzforce.core.PdpConfigurationManager;
import com.thalesgroup.authzforce.core.PdpModelHandler;

public class TestUtils
{
	/**
	 * Global test configuration filename
	 */
	public static final String GLOBAL_TEST_CONF_FILENAME = "src/test/resources/authzforce.test.properties";

	private static final File GLOBAL_TEST_CONF_FILE = new File(GLOBAL_TEST_CONF_FILENAME);

	/**
	 * the logger we'll use for all messages
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(TestUtils.class);

	/**
	 * This creates the XACML request from a file
	 * 
	 * @param rootDirectory
	 *            root directory of the request files
	 * @param versionDirectory
	 *            version directory of the request files
	 * @param requestFilename
	 *            request file name
	 * @return String or null if any error
	 */
	public static Request createRequest(String rootDirectory, String versionDirectory, String requestFilename)
	{

		Document doc = null;
		/**
		 * Get absolute path/URL to request file in a portable way, using current class loader. As
		 * per javadoc, the name of the resource passed to ClassLoader.getResource() is a
		 * '/'-separated path name that identifies the resource. So let's build it. Note: do not use
		 * File.separator as path separator, as it will be turned into backslash "\\" on Windows,
		 * and will be URL-encoded (%5c) by the getResource() method (not considered path separator
		 * by this method), and file will not be found as a result.
		 */
		String requestFileResourceName = rootDirectory + "/" + versionDirectory + "/" + TestConstants.REQUEST_DIRECTORY.value() + "/"
				+ requestFilename;
		URL requestFileURL = Thread.currentThread().getContextClassLoader().getResource(requestFileResourceName);
		try
		{
			LOGGER.debug("Request file to read: {}", requestFileURL);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setIgnoringComments(true);
			factory.setNamespaceAware(true);
			DocumentBuilder db = factory.newDocumentBuilder();
			doc = db.parse(requestFileURL.toString());
		} catch (Exception e)
		{
			LOGGER.error("Error while reading expected request from file ", e);
		}
		return marshallRequestType(doc);
	}

	/**
	 * This creates the expected XACML response from a file
	 * 
	 * @param rootDirectory
	 *            root directory of the response files
	 * @param versionDirectory
	 *            version directory of the response files
	 * @param responseFilename
	 *            response file name
	 * @return ResponseCtx or null if any error
	 */
	public static Response createResponse(String rootDirectory, String versionDirectory, String responseFilename)
	{
		Document doc = null;
		/**
		 * Get absolute path/URL to request file in a portable way, using current class loader. As
		 * per javadoc, the name of the resource passed to ClassLoader.getResource() is a
		 * '/'-separated path name that identifies the resource. So let's build it. Note: do not use
		 * File.separator as path separator, as it will be turned into backslash "\\" on Windows,
		 * and will be URL-encoded (%5c) by the getResource() method (not considered path separator
		 * by this method), and file will not be found as a result.
		 */
		String responseFileResourceName = rootDirectory + "/" + versionDirectory + "/" + TestConstants.RESPONSE_DIRECTORY.value() + "/"
				+ responseFilename;
		URL responseFileURL = Thread.currentThread().getContextClassLoader().getResource(responseFileResourceName);
		try
		{
			LOGGER.debug("Response file to read: {}", responseFileURL);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setIgnoringComments(true);
			factory.setNamespaceAware(true);
			factory.setValidating(false);
			DocumentBuilder db = factory.newDocumentBuilder();
			doc = db.parse(responseFileURL.toString());
		} catch (Exception e)
		{
			LOGGER.error("Error while reading expected response from file ", e);
		}

		return marshallResponseType(doc);
	}

	private static Request marshallRequestType(Node root)
	{
		Request request = null;
		try
		{
			Unmarshaller u = PdpModelHandler.XACML_3_0_JAXB_CONTEXT.createUnmarshaller();
			JAXBElement<Request> jaxbElt = u.unmarshal(root, Request.class);
			request = jaxbElt.getValue();
		} catch (Exception e)
		{
			LOGGER.error("Error unmarshalling Request", e);
		}

		return request;
	}

	private static Response marshallResponseType(Node root)
	{
		Response allOf = null;
		try
		{
			Unmarshaller u = PdpModelHandler.XACML_3_0_JAXB_CONTEXT.createUnmarshaller();
			allOf = (Response) u.unmarshal(root);
		} catch (Exception e)
		{
			LOGGER.error("Error unmarshalling Response", e);
		}

		return allOf;
	}

	public static String printRequest(Request request)
	{
		StringWriter writer = new StringWriter();
		try
		{
			Marshaller u = PdpModelHandler.XACML_3_0_JAXB_CONTEXT.createMarshaller();
			u.marshal(request, writer);
		} catch (Exception e)
		{
			LOGGER.error("Error marshalling Request", e);
		}

		return writer.toString();
	}

	public static String printResponse(Response response)
	{
		StringWriter writer = new StringWriter();
		try
		{
			Marshaller marshaller = PdpModelHandler.XACML_3_0_JAXB_CONTEXT.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
			marshaller.marshal(response, writer);
		} catch (Exception e)
		{
			LOGGER.error("Error marshalling Response", e);
		}

		return writer.toString();
	}

	public static boolean match(ResponseCtx response, Response expectedResponse)
	{

		boolean finalResult = false;

		Response xacmlResponse = new Response();
		Iterator<oasis.names.tc.xacml._3_0.core.schema.wd_17.Result> myIt = response.getResults().iterator();

		while (myIt.hasNext())
		{
			Result result = (Result) myIt.next();
			oasis.names.tc.xacml._3_0.core.schema.wd_17.Result resultType = result;
			xacmlResponse.getResults().add(resultType);
		}

		finalResult = matchResult(xacmlResponse.getResults(), expectedResponse.getResults());
		if (finalResult)
		{
			int i = 0;
			for (oasis.names.tc.xacml._3_0.core.schema.wd_17.Result result : xacmlResponse.getResults())
			{
				finalResult = matchObligations(result.getObligations(), expectedResponse.getResults().get(i).getObligations());
			}
		} else
		{
			// Obligation comparison failed
			LOGGER.error("Result comparaison failed");
			return finalResult;
		}
		if (finalResult)
		{
			int i = 0;
			for (oasis.names.tc.xacml._3_0.core.schema.wd_17.Result result : xacmlResponse.getResults())
			{
				finalResult = matchAdvices(result.getAssociatedAdvice(), expectedResponse.getResults().get(i).getAssociatedAdvice());
			}
		} else
		{
			// Advice comparison failed
			LOGGER.error("Obligations comparaison failed");
			return finalResult;
		}

		if (!finalResult)
		{
			// Advice comparison failed
			LOGGER.error("Advice comparaison failed");
			return finalResult;
		}

		// Everything gone right
		return finalResult;
	}

	private static boolean matchResult(List<oasis.names.tc.xacml._3_0.core.schema.wd_17.Result> currentResult,
			List<oasis.names.tc.xacml._3_0.core.schema.wd_17.Result> expectedResult)
	{
		// Compare the number of results
		LOGGER.debug("Begining result number comparison");
		if (currentResult.size() != expectedResult.size())
		{
			LOGGER.error("Number of result differ from expected");
			LOGGER.error("Current: " + currentResult.size());
			LOGGER.error("Expected: " + expectedResult.size());
			return false;
		}

		LOGGER.debug("Result number comparison OK");
		int i = 0;
		LOGGER.debug("Begining result decision comparaison");
		for (oasis.names.tc.xacml._3_0.core.schema.wd_17.Result result : currentResult)
		{
			// Compare the decision
			final boolean decisionMatch = result.getDecision() == expectedResult.get(i).getDecision();
			if (!decisionMatch)
			{
				LOGGER.error("Result " + i + " differ from expected.");
				LOGGER.error("Current decision: " + result.getDecision());
				LOGGER.error("Expected decision: " + expectedResult.get(i).getDecision());
				return false;
			}

			i++;
		}
		
		LOGGER.debug("Result decision comparaison OK");
		return true;
	}

	private static boolean matchObligations(Obligations obligationsType, Obligations obligationsType2)
	{
		boolean returnData = true;

		if (obligationsType != null && obligationsType2 != null)
		{
			if (!obligationsType.equals(obligationsType2))
			{
				returnData = false;
			}
		}

		return returnData;
	}

	private static boolean matchAdvices(AssociatedAdvice associatedAdvice, AssociatedAdvice associatedAdvice2)
	{
		boolean returnData = true;
		if (associatedAdvice != null && associatedAdvice2 != null)
		{
			if (!associatedAdvice.equals(associatedAdvice2))
			{
				returnData = false;
			}
		}

		return returnData;
	}

	/**
	 * Returns a new PDP instance with new XACML policies and based on configuration in file
	 * {@literal #GLOBAL_TEST_CONF_FILENAME}
	 * 
	 * @param rootDir
	 *            test root directory name
	 * @param versionDir
	 *            XACML version directory name
	 * 
	 * @param policyfilenames
	 *            Set of XACML policy file names
	 * @return a PDP instance
	 */
	public static PDP getPDPNewInstance(String rootDir, String versionDir, Set<String> policyfilenames)
	{
		return getPDPNewInstance(rootDir + "/" + versionDir + "/" + TestConstants.POLICY_DIRECTORY.value() + "/", policyfilenames);
	}

	/**
	 * Creates PDP from policies and global configuration in file
	 * {@literal #GLOBAL_TEST_CONF_FILENAME}
	 * 
	 * @param pathPrefix
	 *            prefix to append before policy filename to have the actual policy file path in the
	 *            classpath
	 * @param policyfilenames
	 *            list of XACML policy filenames relative to pathPrefix. If pathPrefix is null,
	 *            filename is considered at the root of the classpath
	 * @return PDP instance
	 */
	public static PDP getPDPNewInstance(String pathPrefix, Set<String> policyfilenames)
	{

		Properties properties = new Properties();
		try
		{
			properties.load(new FileInputStream(GLOBAL_TEST_CONF_FILE));
		} catch (IOException e)
		{
			throw new RuntimeException(e);
		}

		final String confLocation = properties.getProperty("configFile");
		final PdpConfigurationManager testConfMgr;
		try
		{
			testConfMgr = new PdpConfigurationManager(confLocation);
		} catch (IOException | JAXBException e)
		{
			throw new RuntimeException("Error parsing PDP configuration from location: " + confLocation, e);
		}

		PolicyFinder policyFinder = new PolicyFinder();
		String[] policyLocations = new String[policyfilenames.size()];
		int i = 0;
		for (String policyfilename : policyfilenames)
		{
			/**
			 * Get absolute path/URL to policy file in a portable way, using current class loader.
			 * As per javadoc, the name of the resource passed to ClassLoader.getResource() is a
			 * '/'-separated path name that identifies the resource. So let's build it. Note: do not
			 * use File.separator as path separator, as it will be turned into backslash "\\" on
			 * Windows, and will be URL-encoded (%5c) by the getResource() method (not considered
			 * path separator by this method), and file will not be found as a result.
			 */
			String policyFileResourceName = pathPrefix + policyfilename;
			URL policyFileURL = Thread.currentThread().getContextClassLoader().getResource(policyFileResourceName);
			// Use getPath() to remove the file: prefix, because used later as input to
			// FileInputStream(...) in FilePolicyModule
			policyLocations[i] = policyFileURL.toString();
			i += 1;
		}

		StaticPolicyFinderModule testPolicyFinderModule = new StaticPolicyFinderModule(policyLocations);
		List<PolicyFinderModule<?>> policyModules = new ArrayList<>();
		policyModules.add(testPolicyFinderModule);
		policyFinder.setModules(policyModules);

		PDPConfig pdpConfig = new PDPConfig(testConfMgr.getDefaultPDPConfig().getAttributeFinder(), policyFinder, testConfMgr.getDefaultPDPConfig()
				.getResourceFinder(), null);

		return new PDP(pdpConfig);
	}

	public static EvaluationCtx createContext(Request request)
	{
		BasicEvaluationCtx evaluationCtx = null;
		try
		{
			evaluationCtx = new BasicEvaluationCtx(request);
		} catch (NumberFormatException | ParsingException | UnknownIdentifierException e)
		{
			throw new RuntimeException("Failed to create evaluation context", e);
		}

		return evaluationCtx;
	}
}
