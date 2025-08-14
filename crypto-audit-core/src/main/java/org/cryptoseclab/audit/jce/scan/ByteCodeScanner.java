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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Defines the contract for a bytecode scanner that analyzes Java bytecode files
 * and identifies potential findings.
 */
public interface ByteCodeScanner
{
    /**
     * Scans the specified input file or directory for bytecode and returns a map of findings.
     *
     * @param input the {@link Path} to the file or directory to scan
     * @return a map where the keys are class names and the values are lists of {@link Finding} objects
     * representing issues or observations found during the scan
     * @throws IOException if an I/O error occurs while reading the input
     */
    Map<String, List<Finding>> scan(Path input) throws IOException;
}
