/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.report;

import org.cryptoseclab.audit.policy.Analysis;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A writer that generates text-based reports for analysis results.
 * This implementation organizes the results by class and outputs them
 * in a human-readable format.
 */
public final class TextReportWriter implements ReportWriter
{
    /**
     * Map of class names to their corresponding list of analysis results.
     */
    private final Map<String, List<Analysis>> byClass;

    /**
     * Constructs a new TextReportWriter.
     *
     * @param analysesByClass A map where the key is the class name and the value is a list of analysis results.
     * @throws NullPointerException if the provided map is null.
     */
    public TextReportWriter(final Map<String, List<Analysis>> analysesByClass)
    {
        this.byClass = Objects.requireNonNull(analysesByClass);
    }

    /**
     * Writes the analysis report to the standard output.
     *
     * @throws Exception if an error occurs during writing.
     */
    @Override
    public void write() throws Exception
    {
        for (final var entry : byClass.entrySet()) {
            System.out.printf("%nClass: %s%n", entry.getKey());
            writeClassReport(entry.getValue());
        }
    }

    /**
     * Writes the analysis report for a specific class to the standard output.
     *
     * @param results A list of analysis results for a specific class.
     */
    private void writeClassReport(final List<Analysis> results)
    {
        results.forEach(r -> System.out.printf(
                "class=%s:%d  method=%s  api=%s  algorithm=%s provider=%s verdict=%s  reason=%s  " +
                        "rule=%s%n",
                r.finding().location().className(),
                r.finding().location().line(),
                r.finding().location().methodSignature(),
                r.finding().api(),
                r.finding().args().isEmpty() ? "None" : r.finding().args().get(0).printable(),
                r.finding().args().size() <= 1 ? "None" : r.finding().args().get(1).printable(),
                r.verdict(), r.reason(), r.ruleId()
        ));
        System.out.printf("Total findings: %d%n", results.size());
    }
}
