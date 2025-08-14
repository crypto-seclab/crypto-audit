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
 * Represents a policy for cryptographic algorithms, specifying lists of allowed
 * and denied algorithms, as well as regular expressions for more flexible matching.
 *
 * @param allow      the list of explicitly allowed algorithm names (e.g., "SHA-256"), may be null
 * @param deny       the list of explicitly denied algorithm names (e.g., "MD5"), may be null
 * @param allowRegex the list of regular expressions for allowed algorithm names, may be null
 * @param denyRegex  the list of regular expressions for denied algorithm names, may be null
 */
@Builder(toBuilder = true)
public record Algorithms(
        List<String> allow,
        List<String> deny,
        List<String> allowRegex,
        List<String> denyRegex
)
{
}
