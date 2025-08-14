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

import lombok.Builder;
import org.cryptoseclab.audit.jce.scan.Finding;

/**
 * Represents the result of analyzing a cryptographic operation or configuration
 * against a specific policy and rule set.
 *
 * @param finding  the {@link Finding} object that triggered the analysis, must not be null
 * @param policyId the identifier of the policy being evaluated (e.g., "FIPS-140-3"), must not be null
 * @param ruleId   the identifier of the specific rule or reason code that was matched, must not be null
 * @param verdict  the {@link Verdict} indicating the outcome of the analysis (e.g., ALLOW, DENY), must not be null
 * @param reason   a human-readable explanation of the analysis result, may be null
 */
@Builder(toBuilder = true)
public record Analysis(
        Finding finding,
        String policyId,     // e.g., "FIPS-140-3"
        String ruleId,       // matched rule id or reason code
        Verdict verdict,
        String reason        // human-readable explanation
)
{
}
