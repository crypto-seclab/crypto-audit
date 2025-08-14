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
 * Represents the source code position of a call site.
 * This record provides details about the class, method, source file, and line number
 * where a specific call site is located.
 *
 * @param className       the fully qualified name of the class (e.g., "com.example.Foo")
 * @param methodSignature the method signature, including the return type and parameters
 *                        (e.g., "&lt;com.example.Foo: void bar(java.lang.String)&gt;")
 * @param sourceFile      the name or path of the source file, if available; may default to the class name
 * @param line            the line number in the source file where the call site is located; -1 if unavailable
 */
@Builder(toBuilder = true)
public record Location(
        String className,
        String methodSignature,
        String sourceFile,
        int line
)
{
}
