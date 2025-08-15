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

import java.util.List;

/**
 * Represents a cryptographic policy, which includes a unique identifier,
 * a version, and a list of rules that define the policy's behavior.
 *
 * @param policyId the unique identifier for the policy (e.g., "FIPS-140-3")
 * @param name the human-readable name of the policy (e.g., "FIPS 140-3 Level 1")
 * @param description the description of the policy
 * @param version  the version of the policy (e.g., "1.0")
 * @param rules    the list of {@link Rule} objects that define the policy
 */
@Builder(toBuilder = true)
public record Policy(
        String policyId,
        String name,
        String description,
        String version,
        List<Rule> rules
)
{
}
