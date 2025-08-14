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

/**
 * Represents a captured argument at a call site.
 * This record encapsulates details about an argument, including its index,
 * a printable representation, and an optional resolved literal value.
 *
 * @param index         the zero-based index of the argument in the method call
 * @param printable     a string representation of the argument, must not be null
 * @param literalOrNull the resolved literal value of the argument if known (e.g., "MD5"), or null if not available
 */
@Builder(toBuilder = true)
public record ArgumentValue(
        int index,
        String printable,
        String literalOrNull
)
{
}
