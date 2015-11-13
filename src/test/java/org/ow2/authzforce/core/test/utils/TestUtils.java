/**
 * Copyright (C) 2011-2015 Thales Services SAS.
 *
 * This file is part of AuthZForce.
 *
 * AuthZForce is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * AuthZForce is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with AuthZForce. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.core.test.utils;

import static org.junit.Assert.assertEquals;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.Request;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Response;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Result;

import org.ow2.authzforce.core.DefaultRequestFilter;
import org.ow2.authzforce.core.EvaluationContext;
import org.ow2.authzforce.core.IndeterminateEvaluationException;
import org.ow2.authzforce.core.IndividualDecisionRequest;
import org.ow2.authzforce.core.IndividualDecisionRequestContext;
import org.ow2.authzforce.core.PdpConfigurationParser;
import org.ow2.authzforce.core.RequestFilter;
import org.ow2.authzforce.core.XACMLBindingUtils;
import org.ow2.authzforce.core.expression.ExpressionFactory;
import org.ow2.authzforce.core.expression.ExpressionFactoryImpl;
import org.ow2.authzforce.core.func.StandardFunctionRegistry;
import org.ow2.authzforce.core.value.StandardDatatypeFactoryRegistry;
import org.ow2.authzforce.core.xmlns.pdp.BaseStaticPolicyFinder;
import org.ow2.authzforce.core.xmlns.pdp.Pdp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

import com.sun.xacml.PDP;

public class TestUtils
{
	/**
	 * XACML standard Expression factory/parser
	 */
	public static final ExpressionFactory STD_EXPRESSION_FACTORY;
	static
	{
		try
		{
			STD_EXPRESSION_FACTORY = new ExpressionFactoryImpl(StandardDatatypeFactoryRegistry.INSTANCE, StandardFunctionRegistry.INSTANCE, null, 0, false);
		} catch (IllegalArgumentException | IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * Default (basic) request filter, supporting only XACML core mandatory features of Individual Decision requests (no support for AttributeSelectors)
	 */
	private static final RequestFilter BASIC_REQUEST_FILTER = new DefaultRequestFilter(StandardDatatypeFactoryRegistry.INSTANCE, false, null, null);

	public static final String POLICY_DIRECTORY = "policies";
	public static final String REQUEST_DIRECTORY = "requests";
	public static final String RESPONSE_DIRECTORY = "responses";

	/**
	 * the logger we'll use for all messages
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(TestUtils.class);

	/**
	 * This creates the XACML request from file on classpath
	 * 
	 * @param requestFileLocation
	 *            file path (with Spring-supported URL prefixes: 'classpath:', etc.) path to the request file, relative to classpath
	 * @return the XML/JAXB Request or null if any error
	 * @throws JAXBException
	 *             error reading XACML 3.0 Request from the file at {@code requestFileLocation}
	 * @throws FileNotFoundException
	 *             no file found at {@code requestFileLocation}
	 */
	public static Request createRequest(String requestFileLocation) throws JAXBException, FileNotFoundException
	{
		/**
		 * Get absolute path/URL to request file in a portable way, using current class loader. As per javadoc, the name of the resource passed to
		 * ClassLoader.getResource() is a '/'-separated path name that identifies the resource. So let's build it. Note: do not use File.separator as path
		 * separator, as it will be turned into backslash "\\" on Windows, and will be URL-encoded (%5c) by the getResource() method (not considered path
		 * separator by this method), and file will not be found as a result.
		 */
		URL requestFileURL = ResourceUtils.getURL(requestFileLocation);
		if (requestFileURL == null)
		{
			throw new FileNotFoundException("No XACML Request file found at location: 'classpath:" + requestFileLocation + "'");
		}

		LOGGER.debug("Request file to read: {}", requestFileURL);
		Unmarshaller u = XACMLBindingUtils.createXacml3Unmarshaller();
		Request request = (Request) u.unmarshal(requestFileURL);
		return request;
	}

	/**
	 * This creates the XACML response from file on classpath
	 * 
	 * @param responseFileLocation
	 *            path to the response file (with Spring-supported URL prefixes: 'classpath:', etc.)
	 * @return the XML/JAXB Response or null if any error
	 * @throws JAXBException
	 *             error reading XACML 3.0 Request from the file at {@code responseFileLocation}
	 * @throws FileNotFoundException
	 *             no file found at {@code responseFileLocation}
	 */
	public static Response createResponse(String responseFileLocation) throws JAXBException, FileNotFoundException
	{
		/**
		 * Get absolute path/URL to response file in a portable way, using current class loader. As per javadoc, the name of the resource passed to
		 * ClassLoader.getResource() is a '/'-separated path name that identifies the resource. So let's build it. Note: do not use File.separator as path
		 * separator, as it will be turned into backslash "\\" on Windows, and will be URL-encoded (%5c) by the getResource() method (not considered path
		 * separator by this method), and file will not be found as a result.
		 */
		URL responseFileURL = ResourceUtils.getURL(responseFileLocation);
		LOGGER.debug("Response file to read: {}", responseFileURL);
		Unmarshaller u = XACMLBindingUtils.createXacml3Unmarshaller();
		Response response = (Response) u.unmarshal(responseFileURL);
		return response;
	}

	public static String printResponse(Response response)
	{
		StringWriter writer = new StringWriter();
		try
		{
			Marshaller marshaller = XACMLBindingUtils.createXacml3Marshaller();
			marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
			marshaller.marshal(response, writer);
		} catch (Exception e)
		{
			LOGGER.error("Error marshalling Response", e);
		}

		return writer.toString();
	}

	/**
	 * Normalize a XACML response for comparison with another normalized one. In particular, it removes every Result's status as we choose to ignore the Status.
	 * Indeed, a PDP implementation might return a perfectly XACML-compliant response but with extra StatusCode/Message/Detail that we would not expect.
	 * 
	 * @param response
	 *            input XACML Response
	 */
	private static void normalizeForComparison(Response response)
	{
		/*
		 * We iterate over all results, because for each results, we don't compare everything. In particular, we choose to ignore the Status. Indeed, a PDP
		 * implementation might return a perfectly XACML-compliant response but with extra StatusCode/Message/Detail that we would not expect.
		 */
		for (Result result : response.getResults())
		{
			// We ignore the status, so set it to null in both expected and tested response to avoid
			// Status comparison
			result.setStatus(null);
		}
	}

	/**
	 * Creates PDP from root policy file
	 * 
	 * @param policyLocation
	 *            XACML policy location (with Spring-supported URL prefixes: 'classpath:', etc.)
	 * @return PDP instance
	 * @throws IllegalArgumentException
	 *             invalid XACML policy located at {@code policyLocation}
	 * @throws IOException
	 *             if error closing some resources used by the PDP after {@link IllegalArgumentException} occurred
	 */
	public static PDP getPDPNewInstance(String policyLocation) throws IllegalArgumentException, IOException
	{
		/**
		 * Get absolute path/URL to policy file in a portable way, using current class loader. As per javadoc, the name of the resource passed to
		 * ClassLoader.getResource() is a '/'-separated path name that identifies the resource. So let's build it. Note: do not use File.separator as path
		 * separator, as it will be turned into backslash "\\" on Windows, and will be URL-encoded (%5c) by the getResource() method (not considered path
		 * separator by this method), and file will not be found as a result.
		 */
		URL policyFileURL = ResourceUtils.getURL(policyLocation);
		if (policyFileURL == null)
		{
			throw new FileNotFoundException("No such file: " + policyLocation);
		}

		BaseStaticPolicyFinder jaxbRootPolicyFinder = new BaseStaticPolicyFinder();
		jaxbRootPolicyFinder.setId("root");
		jaxbRootPolicyFinder.setPolicyLocation(policyFileURL.toString());

		Pdp jaxbPDP = new Pdp();
		jaxbPDP.setRootPolicyFinder(jaxbRootPolicyFinder);
		final PDP pdp = PdpConfigurationParser.getPDP(jaxbPDP);
		return pdp;
	}

	public static EvaluationContext createContext(Request request) throws IndeterminateEvaluationException
	{
		/*
		 * The request filter used here does not support, therefore filters out AttributeSelectors, so make sure there's no AttributeSelector in the
		 * Target/Match elements of the PolicySet.
		 */
		IndividualDecisionRequest individualDecisionReq = BASIC_REQUEST_FILTER.filter(request).get(0);
		return new IndividualDecisionRequestContext(individualDecisionReq);
	}

	/**
	 * assertEquals() for XACML responses (handles normalization of the responses)
	 * 
	 * @param testId
	 *            test identifier
	 * @param expectedResponse
	 *            expected response
	 * @param actualResponseFromPDP
	 *            actual response
	 * @throws JAXBException
	 */
	public static void assertNormalizedEquals(String testId, Response expectedResponse, Response actualResponseFromPDP) throws JAXBException
	{
		// normalize responses for comparison
		TestUtils.normalizeForComparison(expectedResponse);
		TestUtils.normalizeForComparison(actualResponseFromPDP);
		assertEquals("Test '" + testId + "' (Status elements removed/ignored for comparison): ", expectedResponse, actualResponseFromPDP);
	}
}