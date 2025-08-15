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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A utility class for loading and normalizing cryptographic policies from YAML files.
 * Provides methods to load a default policy or a policy from a specified file path.
 */
public final class PolicyYamlLoader
{
    private final ObjectMapper om;

    /**
     * Constructs a {@code PolicyYamlLoader} with a pre-configured {@link ObjectMapper}
     * for parsing YAML files. The {@link ParameterNamesModule} is registered to support Java records.
     */
    public PolicyYamlLoader()
    {
        om = new ObjectMapper(new YAMLFactory())
                .registerModule(new ParameterNamesModule());
    }

    /**
     * Normalizes a given {@link Policy} by applying normalization to its rules.
     *
     * @param p the {@link Policy} to normalize
     * @return a normalized {@link Policy} object
     */
    private Policy normalizePolicy(final Policy p)
    {
        final var normRules = p.rules().stream()
                .map(this::normalizeRule)
                .toList();
        return p.toBuilder().rules(normRules).build();
    }

    /**
     * Normalizes a given {@link Rule} by applying normalization to its algorithms and providers.
     *
     * @param r the {@link Rule} to normalize
     * @return a normalized {@link Rule} object
     */
    private Rule normalizeRule(final Rule r)
    {
        return r.toBuilder()
                .algorithms(normalizeAlgorithms(r.algorithms()))
                .providers(normalizeProviders(r.providers()))
                .build();
    }

    /**
     * Normalizes a given {@link Algorithms} object by converting its lists to uppercase
     * and making its regular expressions case-insensitive.
     *
     * @param alg the {@link Algorithms} to normalize
     * @return a normalized {@link Algorithms} object, or null if the input is null
     */
    private Algorithms normalizeAlgorithms(final Algorithms alg)
    {
        if (alg == null) return null;
        return alg.toBuilder()
                .allow(toUpper(alg.allow()))
                .deny(toUpper(alg.deny()))
                .allowRegex(toCaseInsensitive(alg.allowRegex()))
                .denyRegex(toCaseInsensitive(alg.denyRegex()))
                .build();
    }

    /**
     * Normalizes a given {@link Providers} object by converting its lists to uppercase
     * and making its regular expressions case-insensitive.
     *
     * @param prov the {@link Providers} to normalize
     * @return a normalized {@link Providers} object, or null if the input is null
     */
    private Providers normalizeProviders(final Providers prov)
    {
        if (prov == null) return null;
        return prov.toBuilder()
                .allow(toUpper(prov.allow()))
                .deny(toUpper(prov.deny()))
                .allowRegex(toCaseInsensitive(prov.allowRegex()))
                .denyRegex(toCaseInsensitive(prov.denyRegex()))
                .build();
    }

    /**
     * Converts a list of strings to uppercase.
     *
     * @param list the list of strings to convert
     * @return a new list with all strings converted to uppercase, or null if the input is null
     */
    private List<String> toUpper(final List<String> list)
    {
        return list == null ? null :
                list.stream().map(s -> s == null ? null : s.toUpperCase(Locale.ROOT)).toList();
    }

    /**
     * Makes a list of regular expressions case-insensitive by prefixing them with "(?i)".
     *
     * @param regexes the list of regular expressions to modify
     * @return a new list with all regular expressions made case-insensitive, or null if the input is null
     */
    private List<String> toCaseInsensitive(final List<String> regexes)
    {
        return regexes == null ? null :
                regexes.stream().map(s -> s == null ? null : "(?i)" + s).toList();
    }

    /**
     * Loads the default policy from a YAML resource file named "policy-fips-140-2-l1.yaml".
     *
     * @return the loaded {@link Policy} object
     * @throws IOException           if an I/O error occurs while reading the resource
     * @throws IllegalStateException if the resource is not found
     */
    public Policy loadDefaultPolicy() throws IOException
    {
        final String resourceName = "policy-fips-140-2-l1.yaml";
        try (final var in = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(resourceName)) {

            if (in == null) {
                throw new IllegalStateException("Resource not found: %s".formatted(resourceName));
            }

            final var policy = om.readValue(in, Policy.class);
            return normalizePolicy(policy);
        }
    }

    /**
     * Loads a policy from a specified YAML file path and normalizes it.
     *
     * @param path the {@link Path} to the YAML file
     * @return the loaded and normalized {@link Policy} object
     * @throws IOException if an I/O error occurs while reading the file
     */
    public Policy loadPolicy(final Path path) throws IOException
    {
        try (final var in = Files.newInputStream(path)) {
            final var policy = om.readValue(in, Policy.class);
            return normalizePolicy(policy);
        }
    }
}
