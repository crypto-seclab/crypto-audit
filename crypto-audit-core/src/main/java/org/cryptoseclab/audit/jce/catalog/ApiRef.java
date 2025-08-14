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
 * Represents a reference to a Java API, consisting of the fully qualified class name
 * and the method name. Used to identify cryptographic entrypoint in the catalog.
 *
 * @param className  the fully qualified name of the class (e.g., "java.security.MessageDigest"), must not be null
 * @param methodName the name of the method (e.g., "getInstance"), must not be null
 */
@Builder(toBuilder = true)
public record ApiRef(
        String className,          // e.g., "java.security.MessageDigest"
        String methodName          // e.g., "getInstance"
)
{
    /**
     * Constructs an {@code ApiRef} record, ensuring both class name and method name are not null.
     *
     * @param className  the fully qualified class name
     * @param methodName the method name
     * @throws NullPointerException if {@code className} or {@code methodName} is null
     */
    public ApiRef
    {
        Objects.requireNonNull(className, "className");
        Objects.requireNonNull(methodName, "methodName");
    }
}
