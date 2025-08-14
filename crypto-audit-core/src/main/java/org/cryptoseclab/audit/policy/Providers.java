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
 * Represents a set of cryptographic providers, including lists of allowed and denied
 * providers, as well as regular expressions for more flexible matching.
 *
 * @param allow      the list of explicitly allowed provider names (e.g., "BC" for BouncyCastle), may be null
 * @param deny       the list of explicitly denied provider names, may be null
 * @param allowRegex the list of regular expressions for allowed provider names, may be null
 * @param denyRegex  the list of regular expressions for denied provider names, may be null
 */
@Builder(toBuilder = true)
public record Providers(
        List<String> allow,
        List<String> deny,
        List<String> allowRegex,
        List<String> denyRegex
)
{
}
