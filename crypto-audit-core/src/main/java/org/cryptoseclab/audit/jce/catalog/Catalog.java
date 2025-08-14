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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a catalog of cryptographic APIs, including metadata such as
 * catalog ID, version, and a list of API entries.
 *
 * @param catalogId the unique identifier for the catalog (e.g., "jce-entrypoints-v1"), must not be null
 * @param version   the optional semantic version or date of the catalog
 * @param apis      the list of API entries to collect as findings, must not be null
 */
@Builder(toBuilder = true)
public record Catalog(
        String catalogId,
        String version,
        List<ApiEntry> apis
)
{
    /**
     * Constructs a {@code Catalog} record, ensuring that the catalog ID and API list are not null.
     * The API list is defensively copied to ensure immutability.
     *
     * @param catalogId the unique identifier for the catalog
     * @param version   the optional semantic version or date of the catalog
     * @param apis      the list of API entries
     * @throws NullPointerException if {@code catalogId} or {@code apis} is null
     */
    public Catalog
    {
        Objects.requireNonNull(catalogId, "catalogId");
        Objects.requireNonNull(apis, "apis");
        apis = List.copyOf(apis);
    }

    /**
     * Generates a map of API keys to their corresponding argument specifications.
     * The keys are constructed using the fully qualified class name and method name
     * (e.g., "java.security.MessageDigest#getInstance").
     * If an API entry does not have an argument specification, a default one is created.
     * Duplicate keys are ignored, and the first encountered entry is retained.
     *
     * @return a map where the keys are API identifiers and the values are argument specifications
     */
    public Map<String, ArgSpec> argSpecByApi()
    {
        final Map<String, ArgSpec> jceApis = new LinkedHashMap<>();

        for (var entry : this.apis()) {
            final String apiKey = key(
                    entry.api()); // e.g., "java.security.MessageDigest#getInstance"
            final ArgSpec argSpec = entry.argSpec() != null
                    ? entry.argSpec()
                    : ArgSpec.builder().build();
            // If duplicate keys exist, keep the first one encountered
            jceApis.putIfAbsent(apiKey, argSpec);
        }
        return jceApis;
    }

    /**
     * Constructs a unique key for an API using the fully qualified class name
     * and method name, separated by a hash symbol (#).
     *
     * @param clsName    the fully qualified class name
     * @param methodName the method name
     * @return a string representing the unique API key
     */
    public String key(final String clsName, final String methodName)
    {
        return clsName + "#" + methodName;
    }

    /**
     * Constructs a unique key for an API using an {@code ApiRef} object.
     * Delegates to the {@link #key(String, String)} method.
     *
     * @param ref the {@code ApiRef} object containing the class and method names
     * @return a string representing the unique API key
     */
    public String key(final ApiRef ref)
    {
        return key(ref.className(), ref.methodName());
    }
}
