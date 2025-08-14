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

/**
 * Represents the possible outcomes of a policy evaluation.
 * <ul>
 *     <li>PASS - Indicates that the evaluation was successful and compliant.</li>
 *     <li>FAIL - Indicates that the evaluation failed and is non-compliant.</li>
 *     <li>UNKNOWN - Indicates that the evaluation result is inconclusive.</li>
 * </ul>
 */
public enum Verdict
{
    PASS,  // The evaluation passed successfully.
    FAIL,  // The evaluation failed.
    UNKNOWN;  // The evaluation result is unknown.
}
