/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.jce.scan;

import lombok.Builder;

import java.util.List;

/**
 * Represents a crypto-relevant call site discovered in the code.
 * This class is intentionally policy-agnostic and does not enforce specific standards (e.g., FIPS).
 *
 * @param api            the fully qualified API name (e.g., "java.security.MessageDigest.getInstance")
 * @param declaringClass the name of the class declaring the method (e.g., "java.security.MessageDigest")
 * @param methodName     the name of the method being called (e.g., "getInstance")
 * @param subSignature   the method's full signature (e.g., "java.security.MessageDigest getInstance(java.lang.String)")
 * @param args           the list of {@link ArgumentValue} objects representing captured arguments at the call site
 * @param location       the {@link Location} object specifying the file, line, and other location details
 */
@Builder(toBuilder = true)
public record Finding(
        String api,
        String declaringClass,
        String methodName,
        String subSignature,
        List<ArgumentValue> args,
        Location location
)
{
}
