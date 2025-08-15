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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A utility class for loading cryptographic API catalogs from YAML files.
 * Provides methods to load a default catalog from a resource or a catalog from a file path.
 */
public final class CatalogYamlLoader
{
    private final ObjectMapper om;

    /**
     * Constructs a {@code CatalogYamlLoader} with a pre-configured {@link ObjectMapper}
     * for parsing YAML files. The {@link ParameterNamesModule} is registered to support Java records.
     */
    public CatalogYamlLoader()
    {
        this.om = new ObjectMapper(new YAMLFactory())
                .registerModule(new ParameterNamesModule()); // for Java records
    }

    /**
     * Loads the default catalog from a YAML resource file named "crypto-catalog-jce.yaml".
     *
     * @return the loaded {@link Catalog} object
     * @throws IOException           if an I/O error occurs while reading the resource
     * @throws IllegalStateException if the resource is not found
     */
    public Catalog loadDefaultCatalog() throws IOException
    {
        final String resourceName = "crypto-catalog-jce.yaml";
        try (final var in = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(resourceName)) {

            if (in == null) {
                throw new IllegalStateException("Resource not found: %s".formatted(resourceName));
            }

            return om.readValue(in, Catalog.class);
        }
    }

    /**
     * Loads a catalog from a specified YAML file path.
     *
     * @param path the {@link Path} to the YAML file
     * @return the loaded {@link Catalog} object
     * @throws IOException if an I/O error occurs while reading the file
     */
    public Catalog loadCatalog(final Path path) throws IOException
    {
        try (final var in = Files.newInputStream(path)) {
            return om.readValue(in, Catalog.class);
        }
    }
}
