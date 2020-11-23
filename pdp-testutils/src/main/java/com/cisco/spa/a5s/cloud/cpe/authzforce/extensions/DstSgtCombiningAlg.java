package com.cisco.spa.a5s.cloud.cpe.authzforce.extensions;

import com.google.common.collect.ImmutableList;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.DecisionType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Status;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.StatusCode;
import org.ow2.authzforce.core.pdp.api.*;
import org.ow2.authzforce.core.pdp.api.combining.BaseCombiningAlg;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlg;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlgParameter;
import org.ow2.authzforce.core.pdp.api.combining.ParameterAssignment;
import org.ow2.authzforce.core.pdp.api.policy.PolicyEvaluator;
import org.ow2.authzforce.core.pdp.api.policy.PrimaryPolicyMetadata;
import org.ow2.authzforce.core.pdp.api.value.IntegerValue;
import org.ow2.authzforce.core.pdp.api.value.StandardDatatypes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class DstSgtCombiningAlg extends BaseCombiningAlg<PolicyEvaluator> {
    public static final String ID = "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:a5s-dst-sgt";
    public static final String POLICY_COMBINER_PARAMETER_NAME_DST_SGT = "dst-sgt";
    public static final String PEP_ACTION_DST_SGT = "urn:oasis:names:tc:xacml:3.0:pep-action:dst-sgt";

    private static final class Evaluator extends BaseCombiningAlg.Evaluator<PolicyEvaluator>
    {
        private final Logger LOG = LoggerFactory.getLogger(getClass());
        private final Map<String, PepActionAttributeAssignment<IntegerValue>> sgtMap;

        private Evaluator(final Iterable<CombiningAlgParameter<? extends PolicyEvaluator>> params, final Iterable<? extends PolicyEvaluator> combinedElements)
        {
            super(combinedElements);
            this.sgtMap = StreamSupport
                    .stream(params.spliterator(), false)
                    .collect(Collectors.toMap(policyCombinerParameters -> policyCombinerParameters.getCombinedElement().getPolicyId(), this::getSgt));
        }

        @Override
        public ExtendedDecision evaluate(final EvaluationContext context, final UpdatableList<PepAction> outPepActions, final UpdatableList<PrimaryPolicyMetadata> outApplicablePolicyIdList)
        {
            List<PepActionAttributeAssignment<IntegerValue>> policyEvalResults = StreamSupport
                    .stream(getCombinedElements().spliterator(), false)
                    .map(policyEvaluator -> evaluatePolicy(context, policyEvaluator))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            PepAction pepAction = new PepAction(PEP_ACTION_DST_SGT, false, ImmutableList.copyOf(policyEvalResults));
            outPepActions.add(pepAction);
            return ExtendedDecisions.getPermit(
                    new Status(
                            new StatusCode(null, "0"),
                            "evaluation success",
                            null)
            );
        }

        private PepActionAttributeAssignment<IntegerValue> evaluatePolicy(final EvaluationContext context, PolicyEvaluator policyEvaluator) {
            DecisionResult policyDecision = policyEvaluator.evaluate(context);
            LOG.debug("Policy [{}] decision result is: [{}]", policyEvaluator.getPolicyId(), policyDecision.getDecision());
            if (policyDecision.getDecision() == DecisionType.PERMIT) {
                PepActionAttributeAssignment<IntegerValue> dstSgt = sgtMap.get(policyEvaluator.getPolicyId());
                if (dstSgt != null) {
                    LOG.debug("Permit access to DST SGT [{}].", dstSgt.getValue());
                    return dstSgt;
                } else {
                    LOG.error("No DST SGT assigned for policy [{}].", policyEvaluator.getPolicyId());
                    return null;
                }
            } else {
                LOG.warn("Decision [{}] for policy [{}].", policyDecision.getDecision().value(), policyEvaluator.getPolicyId());
                return null;
            }
        }

        private PepActionAttributeAssignment<IntegerValue> getSgt(CombiningAlgParameter<? extends PolicyEvaluator> policyCombinerParameters) {
            Optional<ParameterAssignment> sgtAssignment = policyCombinerParameters
                    .getParameters()
                    .stream()
                    .filter(policyCombinerParameter -> policyCombinerParameter.getParameterName().equals(POLICY_COMBINER_PARAMETER_NAME_DST_SGT))
                    .findFirst();
            IntegerValue sgtValue = getSgt(sgtAssignment);
            return new PepActionAttributeAssignment<>(POLICY_COMBINER_PARAMETER_NAME_DST_SGT, Optional.empty(), Optional.empty(), StandardDatatypes.INTEGER, sgtValue);
        }

        private IntegerValue getSgt(Optional<ParameterAssignment> sgtAssignment) {
            if(sgtAssignment.isPresent()) {
                try {
                    int value = Integer.parseInt(String.valueOf(sgtAssignment.get().getValue()));
                    return IntegerValue.valueOf(value);
                } catch (Exception exception) {
                    return null;
                }
            } else {
                return null;
            }
        }
    }

    public DstSgtCombiningAlg() {
        super(ID, PolicyEvaluator.class);
    }

    @Override
    public CombiningAlg.Evaluator getInstance(Iterable<CombiningAlgParameter<? extends PolicyEvaluator>> params, Iterable<? extends PolicyEvaluator> combinedElements) throws UnsupportedOperationException, IllegalArgumentException {
        return new Evaluator(params, combinedElements);
    }
}