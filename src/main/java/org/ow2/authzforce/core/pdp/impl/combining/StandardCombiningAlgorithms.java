/**
 * Copyright (C) 2012-2016 Thales Services SAS.
 *
 * This file is part of AuthZForce CE.
 *
 * AuthZForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthZForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthZForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.core.pdp.impl.combining;

import java.util.EnumSet;
import java.util.Set;
import java.util.TreeSet;

import org.ow2.authzforce.core.pdp.api.Decidable;
import org.ow2.authzforce.core.pdp.api.PdpExtensionRegistry.PdpExtensionComparator;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlg;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlgRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.koloboke.collect.set.hash.HashObjSets;

/**
 * Utilities to handle the XACML core standard combining algorithms
 * 
 * @version $Id: $
 */
public final class StandardCombiningAlgorithms
{

	/**
	 * Standard combining algorithm key for reference (in order to retrieve standard identifier)
	 */
	public enum StdAlgKey
	{
		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides
		 */
		XACML_3_0_POLICY_COMBINING_DENY_OVERRIDES("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides
		 */
		XACML_3_0_RULE_COMBINING_DENY_OVERRIDES("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-deny-overrides
		 */
		XACML_3_0_POLICY_COMBINING_ORDERED_DENY_OVERRIDES("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-deny-overrides
		 */
		XACML_3_0_RULE_COMBINING_ORDERED_DENY_OVERRIDES("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides
		 */
		XACML_3_0_POLICY_COMBINING_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides
		 */
		XACML_3_0_RULE_COMBINING_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-permit-overrides
		 */
		XACML_3_0_POLICY_COMBINING_ORDERED_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-deny-overrides
		 */
		XACML_3_0_RULE_COMBINING_ORDERED_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-unless-permit
		 */
		XACML_3_0_POLICY_COMBINING_DENY_UNLESS_PERMIT("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-unless-permit"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit
		 */
		XACML_3_0_RULE_COMBINING_DENY_UNLESS_PERMIT("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-unless-deny
		 */
		XACML_3_0_POLICY_COMBINING_PERMIT_UNLESS_DENY("urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-unless-deny"),

		/**
		 * urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-unless-deny
		 */
		XACML_3_0_RULE_COMBINING_PERMIT_UNLESS_DENY("urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-unless-deny"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable
		 */
		XACML_1_0_POLICY_COMBINING_FIRST_APPLICABLE("urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable
		 */
		XACML_1_0_RULE_COMBINING_FIRST_APPLICABLE("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:only-one-applicable
		 */
		XACML_1_0_POLICY_COMBINING_ONLY_ONE_APPLICABLE("urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:only-one-applicable"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides
		 */
		XACML_1_0_POLICY_COMBINING_DENY_OVERRIDES("urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides
		 */
		XACML_1_0_RULE_COMBINING_DENY_OVERRIDES("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-deny-overrides
		 */
		XACML_1_1_POLICY_COMBINING_ORDERED_DENY_OVERRIDES("urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides
		 */
		XACML_1_1_RULE_COMBINING_ORDERED_DENY_OVERRIDES("urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides
		 */
		XACML_1_0_POLICY_COMBINING_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides
		 */
		XACML_1_0_RULE_COMBINING_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-permit-overrides
		 */
		XACML_1_1_POLICY_COMBINING_ORDERED_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-permit-overrides"),

		/**
		 * urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides
		 */
		XACML_1_1_RULE_COMBINING_ORDERED_PERMIT_OVERRIDES("urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides");

		private final String id;

		private StdAlgKey(final String id)
		{
			this.id = id;
		}

		/**
		 * @return standard identifier of the algorithm, as defined in the XACML spec
		 */
		public String getStdId()
		{
			return this.id;
		}
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(StandardCombiningAlgorithms.class);

	private static final PdpExtensionComparator<CombiningAlg<?>> COMPARATOR = new PdpExtensionComparator<>();

	/**
	 * Singleton immutable instance of combining algorithm registry for standard algorithms
	 */
	public static final CombiningAlgRegistry REGISTRY;
	static
	{
		final Set<CombiningAlg<? extends Decidable>> standardAlgorithms = HashObjSets
				.newUpdatableSet(StdAlgKey.values().length);
		// XACML 3.0 algorithms
		// deny-overrides and ordered-deny-overrides
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_3_0_POLICY_COMBINING_DENY_OVERRIDES,
				StdAlgKey.XACML_3_0_RULE_COMBINING_ORDERED_DENY_OVERRIDES))
		{
			standardAlgorithms.add(new DenyOverridesAlg(alg.id));
		}

		// permit-overrides and ordered-permit-overrides
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_3_0_POLICY_COMBINING_PERMIT_OVERRIDES,
				StdAlgKey.XACML_3_0_RULE_COMBINING_ORDERED_PERMIT_OVERRIDES))
		{
			standardAlgorithms.add(new PermitOverridesAlg(alg.id));
		}

		// deny-unless-permit
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_3_0_POLICY_COMBINING_DENY_UNLESS_PERMIT,
				StdAlgKey.XACML_3_0_RULE_COMBINING_DENY_UNLESS_PERMIT))
		{
			standardAlgorithms.add(new DenyUnlessPermitAlg(alg.id));
		}

		// permit-unless-deny
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_3_0_POLICY_COMBINING_PERMIT_UNLESS_DENY,
				StdAlgKey.XACML_3_0_RULE_COMBINING_PERMIT_UNLESS_DENY))
		{
			standardAlgorithms.add(new PermitUnlessDenyAlg(alg.id));
		}

		// first-applicable
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_1_0_POLICY_COMBINING_FIRST_APPLICABLE,
				StdAlgKey.XACML_1_0_RULE_COMBINING_FIRST_APPLICABLE))
		{
			standardAlgorithms.add(new FirstApplicableAlg(alg.id));
		}

		// only-one-applicable
		standardAlgorithms.add(new OnlyOneApplicableAlg(StdAlgKey.XACML_1_0_POLICY_COMBINING_ONLY_ONE_APPLICABLE.id));

		//
		// Legacy
		// (ordered-)deny-overrides
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_1_0_POLICY_COMBINING_DENY_OVERRIDES,
				StdAlgKey.XACML_1_1_RULE_COMBINING_ORDERED_DENY_OVERRIDES))
		{
			standardAlgorithms.add(new LegacyDenyOverridesAlg(alg.id));
		}

		// (orderered-)permit-overrides
		for (final StdAlgKey alg : EnumSet.range(StdAlgKey.XACML_1_0_POLICY_COMBINING_PERMIT_OVERRIDES,
				StdAlgKey.XACML_1_1_RULE_COMBINING_ORDERED_PERMIT_OVERRIDES))
		{
			standardAlgorithms.add(new LegacyPermitOverridesAlg(alg.id));
		}

		REGISTRY = new ImmutableCombiningAlgRegistry(standardAlgorithms);
		if (LOGGER.isDebugEnabled())
		{
			final TreeSet<CombiningAlg<?>> sortedAlgorithms = new TreeSet<>(COMPARATOR);
			sortedAlgorithms.addAll(standardAlgorithms);
			LOGGER.debug("Loaded XACML standard combining algorithms: {}", sortedAlgorithms);
		}
	}

	private StandardCombiningAlgorithms()
	{
		// prevent instantiation
	}

}