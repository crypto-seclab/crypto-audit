/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.policy;

import org.cryptoseclab.audit.jce.scan.Finding;

/**
 * Defines the contract for a policy engine that evaluates cryptographic findings
 * against a given policy. Implementations of this interface are responsible for
 * determining whether a finding complies with the specified policy.
 */
public interface PolicyEngine
{
    /**
     * Evaluates a cryptographic finding against a given policy and returns the analysis result.
     *
     * @param finding the {@link Finding} object representing the cryptographic operation or configuration to evaluate, must not be null
     * @param policy  the {@link Policy} object defining the rules and constraints to evaluate against, must not be null
     * @return an {@link Analysis} object containing the evaluation result, including the verdict and reasoning
     */
    Analysis evaluate(Finding finding, Policy policy);
}
