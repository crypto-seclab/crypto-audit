/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.fips;

import org.cryptoseclab.audit.jce.catalog.ArgSpec;
import org.cryptoseclab.audit.jce.catalog.Catalog;
import org.cryptoseclab.audit.jce.scan.Finding;
import org.cryptoseclab.audit.policy.Algorithms;
import org.cryptoseclab.audit.policy.Analysis;
import org.cryptoseclab.audit.policy.Policy;
import org.cryptoseclab.audit.policy.PolicyEngine;
import org.cryptoseclab.audit.policy.Providers;
import org.cryptoseclab.audit.policy.Rule;
import org.cryptoseclab.audit.policy.Verdict;

import java.util.Locale;
import java.util.Map;

/**
 * Implements the FIPS (Federal Information Processing Standards) policy engine.
 * This class evaluates cryptographic findings against a given policy to determine compliance.
 */
public final class FipsPolicyEngine implements PolicyEngine
{
    private final Map<String, ArgSpec> jceApis;
    private final Catalog catalog;

    /**
     * Constructs a new FipsPolicyEngine instance.
     *
     * @param catalog the {@link Catalog} containing cryptographic API specifications
     */
    public FipsPolicyEngine(final Catalog catalog)
    {
        this.catalog = catalog;
        jceApis = this.catalog.argSpecByApi();
    }

    /**
     * Evaluates a cryptographic finding against a specific rule in the policy.
     *
     * @param f      the {@link Finding} to evaluate
     * @param policy the {@link Policy} containing the rules
     * @param rule   the {@link Rule} to evaluate against
     * @return an {@link Analysis} object containing the evaluation result
     */
    private Analysis evaluateAgainstRule(final Finding f, final Policy policy, final Rule rule)
    {
        if (!hasAlgorithmArg(f)) {
            return res(f, policy, id(rule), Verdict.PASS, "DEFAULT_ALGO_ALLOWED");
        }

        final String algo = extractAlgorithmLiteral(f);
        if (algo == null) {
            return res(f, policy, id(rule), Verdict.UNKNOWN, "ALGO_UNRESOLVED");
        }

        final Algorithms algos = rule.algorithms();
        if (algos == null) return res(f, policy, id(rule), Verdict.UNKNOWN, "NO_ALGORITHM_POLICY");

        // Deny check
        if (matchesDenied(algos, algo)) {
            return res(f, policy, id(rule), Verdict.FAIL, "ALGO_DENIED");
        }

        if (algos.allow() != null || algos.allowRegex() != null) {
            if (!matchesAllowed(algos, algo)) {
                return res(f, policy, id(rule), Verdict.FAIL, "ALGO_NOT_ALLOWED");
            }
        }

        // Provider logic after algo allowed
        final Providers prov = rule.providers();

        if (!hasProviderArg(f)) {
            return res(f, policy, id(rule), Verdict.PASS, "ALLOWED_ALGO_DEFAULT_PROVIDER");
        }

        final String providerName = extractProviderLiteral(f);
        if (providerName == null) {
            return res(f, policy, id(rule), Verdict.UNKNOWN, "PROVIDER_UNRESOLVED");
        }

        final String P = providerName.toUpperCase(Locale.ROOT);
        if (prov != null && prov.deny() != null && prov.deny().contains(P))
            return res(f, policy, id(rule), Verdict.FAIL, "PROVIDER_DENIED:" + providerName);

        if (prov != null && prov.allow() != null && !prov.allow().isEmpty() && !prov.allow()
                .contains(P))
            return res(f, policy, id(rule), Verdict.FAIL, "PROVIDER_NOT_ALLOWED:" + providerName);

        return res(f, policy, id(rule), Verdict.PASS, "ALLOWED_ALGO");
    }

    /**
     * Evaluates a cryptographic finding against a given policy.
     *
     * @param f      the {@link Finding} to evaluate
     * @param policy the {@link Policy} to evaluate the finding against
     * @return an {@link Analysis} object containing the evaluation result
     */
    @Override
    public Analysis evaluate(final Finding f, final Policy policy)
    {
        final var rules = policy.rules().stream()
                .filter(r -> r.api().equals(f.api()))
                .toList();

        if (rules.isEmpty()) {
            return res(f, policy, "NO_POLICY_RULE", Verdict.UNKNOWN, "No rule for API");
        }

        Analysis firstFail = null;

        for (final Rule r : rules) {
            Analysis a = evaluateAgainstRule(f, policy, r); // single-rule logic
            // ensure ruleId is set to the rule that produced this result
            if (a.ruleId() == null || a.ruleId().isBlank()) {
                a = a.toBuilder().ruleId(id(r)).build();
            }

            switch (a.verdict()) {
                case PASS:
                    return a; // short-circuit on PASS
                case UNKNOWN:
                    return a; // short-circuit on UNKNOWN
                case FAIL:
                    firstFail = a; // remember earliest FAIL
                    // keep trying other rules
                    break;
            }
        }
        return firstFail != null
                ? firstFail
                : res(f, policy, "NO_DECISION", Verdict.UNKNOWN, "NO_DECISION");
    }

    /**
     * Retrieves the rule ID or a default value if the rule ID is null.
     *
     * @param r the {@link Rule} to retrieve the ID from
     * @return the rule ID or "RULE" if the ID is null
     */
    private String id(final Rule r)
    {
        return r.id() != null ? r.id() : "RULE";
    }

    /**
     * Checks if the finding has an algorithm argument.
     *
     * @param f the {@link Finding} to check
     * @return true if the finding has an algorithm argument, false otherwise
     */
    private boolean hasAlgorithmArg(final Finding f)
    {
        final ArgSpec spec = jceApis.get(catalog.key(f.declaringClass(), f.methodName()));
        if (spec == null) return false;
        final Integer idx = spec.algorithmIndex();
        return idx != null && idx >= 0 && idx < f.args().size();
    }

    /**
     * Extracts the algorithm literal from the finding.
     *
     * @param f the {@link Finding} to extract the algorithm from
     * @return the algorithm literal or null if not available
     */
    private String extractAlgorithmLiteral(final Finding f)
    {
        final ArgSpec spec = jceApis.get(catalog.key(f.declaringClass(), f.methodName()));
        if (spec == null) return null;

        final Integer idx = spec.algorithmIndex();
        if (idx != null && idx >= 0 && idx < f.args().size()) {
            var arg = f.args().get(idx);
            return arg.literalOrNull();
        }
        return null;
    }

    /**
     * Checks if the finding has a provider argument.
     *
     * @param f the {@link Finding} to check
     * @return true if the finding has a provider argument, false otherwise
     */
    private boolean hasProviderArg(final Finding f)
    {
        final ArgSpec spec = jceApis.get(catalog.key(f.declaringClass(), f.methodName()));
        if (spec == null) return false;
        final Integer idx = spec.providerNameIndex();
        return idx != null && idx >= 0 && idx < f.args().size();
    }

    /**
     * Extracts the provider literal from the finding.
     *
     * @param f the {@link Finding} to extract the provider from
     * @return the provider literal or null if not available
     */
    private String extractProviderLiteral(final Finding f)
    {
        final ArgSpec spec = jceApis.get(catalog.key(f.declaringClass(), f.methodName()));
        if (spec == null) return null;

        final Integer idx = spec.providerNameIndex();
        if (idx != null && idx >= 0 && idx < f.args().size()) {
            var arg = f.args().get(idx);
            return arg.literalOrNull();
        }
        return null;
    }

    /**
     * Creates an {@link Analysis} result for the given finding, policy, rule ID, verdict, and reason.
     *
     * @param f      the {@link Finding} being analyzed
     * @param p      the {@link Policy} being applied
     * @param ruleId the ID of the rule being evaluated
     * @param v      the {@link Verdict} of the analysis
     * @param reason the reason for the verdict
     * @return the {@link Analysis} result
     */
    private Analysis res(final Finding f, final Policy p, final String ruleId, final Verdict v,
                         final String reason)
    {
        return Analysis.builder().finding(f).policyId(p.policyId()).ruleId(ruleId).verdict(v)
                .reason(reason).build();
    }

    /**
     * Checks if the given algorithm matches any allowed algorithms or patterns.
     *
     * @param algs the {@link Algorithms} object containing allowed algorithms and patterns
     * @param algo the algorithm to check
     * @return true if the algorithm is allowed, false otherwise
     */
    private boolean matchesAllowed(final Algorithms algs, final String algo)
    {
        final String ALGO = algo.toUpperCase(Locale.ROOT);

        if (algs.allow() != null && !algs.allow().isEmpty()) {
            if (algs.allow().contains(ALGO)) return true;
        }

        if (algs.allowRegex() != null && !algs.allowRegex().isEmpty()) {
            for (String regex : algs.allowRegex()) {
                if (ALGO.matches(regex)) return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given algorithm matches any denied algorithms or patterns.
     *
     * @param algorithms the {@link Algorithms} object containing denied algorithms and patterns
     * @param algo       the algorithm to check
     * @return true if the algorithm is denied, false otherwise
     */
    private boolean matchesDenied(final Algorithms algorithms, final String algo)
    {
        final String ALGO = algo.toUpperCase(Locale.ROOT);

        if (algorithms.deny() != null && algorithms.deny().contains(ALGO)) return true;

        if (algorithms.denyRegex() != null && !algorithms.denyRegex().isEmpty()) {
            for (String regex : algorithms.denyRegex()) {
                if (ALGO.matches(regex)) return true;
            }
        }
        return false;
    }
}
