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

/**
 * Represents the positions of important parameters in an API call.
 * Each index is zero-based, and a null value indicates that the parameter
 * is not applicable or should be ignored.
 */
@Builder(toBuilder = true)
public record ArgSpec(
        /*
         * The index of the algorithm parameter in the API call.
         * Typically, this is 0 (e.g., for "SHA-256").
         * A null value means the algorithm parameter is not applicable.
         */
        Integer algorithmIndex,

        /*
         * The index of the provider name parameter in the API call.
         * This is used for overloads that accept a String provider name.
         * A null value means the provider name parameter is not applicable.
         */
        Integer providerNameIndex,

        /*
         * The index of the provider object parameter in the API call.
         * This is used for overloads that accept a Provider object.
         * A null value means the provider object parameter is not applicable.
         */
        Integer providerObjectIndex
)
{
    /**
     * Constructs an {@code ArgSpec} record, initializing default values
     * for any null indices. If an index is null, it is set to a default value:
     * - {@code algorithmIndex} defaults to 0.
     * - {@code providerNameIndex} defaults to 1.
     * - {@code providerObjectIndex} defaults to 1.
     *
     * @param algorithmIndex      the index of the algorithm parameter
     * @param providerNameIndex   the index of the provider name parameter
     * @param providerObjectIndex the index of the provider object parameter
     */
    public ArgSpec
    {
        algorithmIndex = (algorithmIndex == null) ? 0 : algorithmIndex;
        providerNameIndex = (providerNameIndex == null) ? 1 : providerNameIndex;
        providerObjectIndex = (providerObjectIndex == null) ? 1 : providerObjectIndex;
    }
}
