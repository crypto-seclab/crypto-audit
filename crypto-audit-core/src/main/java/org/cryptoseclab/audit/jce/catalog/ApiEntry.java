/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.jce.catalog;

import lombok.Builder;

import java.util.Objects;

/**
 * Represents an API entry in the catalog, consisting of a reference to the API
 * (declaring class and method name) and an optional argument specification
 * indicating where to find algorithm or provider arguments.
 *
 * @param api     the API reference (class and method name), must not be null
 * @param argSpec specification for argument positions (maybe null)
 */
@Builder(toBuilder = true)
public record ApiEntry(
        ApiRef api,                // declaring class + method name
        ArgSpec argSpec            // where to find algorithm/provider args (maybe null)
)
{
    /**
     * Constructs an {@code ApiEntry} record, ensuring the API reference is not null.
     *
     * @param api     the API reference
     * @param argSpec the argument specification (maybe null)
     * @throws NullPointerException if {@code api} is null
     */
    public ApiEntry
    {
        Objects.requireNonNull(api, "api");
    }
}
