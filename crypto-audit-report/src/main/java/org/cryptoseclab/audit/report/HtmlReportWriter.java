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

import org.cryptoseclab.audit.jce.scan.ArgumentValue;
import org.cryptoseclab.audit.jce.scan.Finding;
import org.cryptoseclab.audit.policy.Analysis;
import org.cryptoseclab.audit.policy.Verdict;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Writes cryptographic analysis results to HTML reports using FreeMarker templates.
 * Generates a summary index and per-class report pages.
 */
public final class HtmlReportWriter implements ReportWriter
{
    /**
     * Map of class names to their corresponding list of analysis results.
     */
    private final Map<String, List<Analysis>> byClass;

    /**
     * Output directory for generated HTML reports.
     */
    private final Path outputDir;

    /**
     * FreeMarker helper for rendering templates.
     */
    private final FreeMarkerHelper Fm = new FreeMarkerHelper();

    /**
     * Constructs an HtmlReportWriter.
     *
     * @param analysesByClass map of class names to analysis results
     * @param outputDir       output directory for reports
     */
    public HtmlReportWriter(final Map<String, List<Analysis>> analysesByClass, final Path outputDir)
    {
        this.byClass = Objects.requireNonNull(analysesByClass);
        this.outputDir = Objects.requireNonNull(outputDir);
    }

    /**
     * Converts a class name to a safe HTML file name.
     *
     * @param className the class name
     * @return the file name for the class report
     */
    private String fileName(final String className)
    {
        return className.replace('.', '_') + ".html";
    }

    /**
     * Safely retrieves the line number from a finding's location.
     *
     * @param f the finding
     * @return the line number, or -1 if unavailable
     */
    private int safeLine(final Finding f)
    {
        try {
            return f.location().line();
        } catch (final Exception e) {
            return -1;
        }
    }

    /**
     * Displays the first argument of a finding, preferring resolved literal.
     *
     * @param f the finding
     * @return the display value for argument 0
     */
    private String algo(final Finding f)
    {
        if (f.args().isEmpty()) return "None";
        final ArgumentValue a0 = f.args().get(0);
        return a0.printable();
    }

    private String prov(final Finding f)
    {
        if (f.args().size() <= 1) return "None";
        final ArgumentValue a1 = f.args().get(1);
        return a1.printable();
    }

    /**
     * Returns an empty string if the input is null.
     *
     * @param s the input string
     * @return the input or empty string if null
     */
    private String nvl(final String s)
    {
        return s == null ? "" : s;
    }

    /**
     * Copies a resource from the classpath to the destination path.
     *
     * @param resourcePath the resource path
     * @param dest         the destination path
     * @throws IOException if an I/O error occurs
     */
    private void copyResource(final String resourcePath, final Path dest) throws IOException
    {
        try (final InputStream in = HtmlReportWriter.class.getResourceAsStream(resourcePath)) {
            if (in == null) throw new NoSuchFileException("Missing resource: " + resourcePath);
            Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Writes all HTML reports: summary index and per-class pages.
     *
     * @throws Exception if an error occurs during writing
     */
    @Override
    public void write() throws Exception
    {
        Files.createDirectories(outputDir.resolve("classes"));
        copyStatic();

        writeIndex();
        // Only write pages for classes that have FAIL/UNKNOWN
        for (final var e : byClass.entrySet()) {
            if (hasIssues(e.getValue())) {
                writeClassPage(e.getKey(), e.getValue());
            }
        }
    }

    /**
     * Checks if the analysis list contains any FAIL or UNKNOWN verdicts.
     *
     * @param list the list of analyses
     * @return true if there are issues, false otherwise
     */
    private boolean hasIssues(final List<Analysis> list)
    {
        return list.stream()
                .anyMatch(a -> a.verdict() == Verdict.FAIL || a.verdict() == Verdict.UNKNOWN);
    }

    /**
     * Builds a model map for a class row in the index.
     *
     * @param cls  the class name
     * @param list the list of analyses for the class
     * @return a map representing the class row
     */
    private Map<String, Object> classRowModel(final String cls, final List<Analysis> list)
    {
        final long t = list.size();
        final long p = list.stream().filter(a -> a.verdict() == Verdict.PASS).count();
        final long f = list.stream().filter(a -> a.verdict() == Verdict.FAIL).count();
        final long u = list.stream().filter(a -> a.verdict() == Verdict.UNKNOWN).count();
        return Map.of(
                "className", cls,
                "fileName", fileName(cls),
                "total", t, "pass", p, "fail", f, "unknown", u
        );
    }

    /**
     * Writes the summary index HTML page.
     *
     * @throws Exception if an error occurs during writing
     */
    private void writeIndex() throws Exception
    {
        final long total = byClass.values().stream().mapToLong(List::size).sum();
        final long pass = count(Verdict.PASS);
        final long fail = count(Verdict.FAIL);
        final long unknown = count(Verdict.UNKNOWN);

        final List<String> ordered = byClass.keySet().stream().sorted().toList();
        final List<Map<String, Object>> issue = new ArrayList<>();
        final List<Map<String, Object>> clean = new ArrayList<>();
        for (final String cls : ordered) {
            final List<Analysis> list = byClass.get(cls);
            if (hasIssues(list)) issue.add(classRowModel(cls, list));
            else clean.add(classRowModel(cls, list));
        }

        final Map<String, Object> model = Map.of(
                "summary", Map.of("total", total, "pass", pass, "fail", fail, "unknown", unknown),
                "issueClasses", issue,
                "cleanClasses", clean
        );

        try (final Writer out = Files.newBufferedWriter(outputDir.resolve("index.html"))) {
            Fm.render("index.ftl", model, out);
        }
    }

    /**
     * Writes the HTML report for a single class.
     *
     * @param className the class name
     * @param analyses  list of analysis results for the class
     * @throws Exception if an error occurs during writing
     */
    private void writeClassPage(final String className, final List<Analysis> analyses) throws Exception
    {
        final List<Analysis> sorted = analyses.stream()
                .sorted(Comparator.comparingInt((final Analysis a) -> safeLine(a.finding()))
                        .thenComparing(a -> a.finding().api()))
                .toList();

        final List<Map<String, Object>> rows = new ArrayList<>();
        for (final Analysis a : sorted) {
            final Finding f = a.finding();
            rows.add(Map.of(
                    "line", safeLine(f),
                    "method", f.location().methodSignature(),
                    "api", f.api(),
                    "algo", algo(f),
                    "prov", prov(f),
                    "verdict", a.verdict().name(),
                    "reason", nvl(a.reason()),
                    "policy", nvl(a.ruleId())
            ));
        }

        final Map<String, Object> model = Map.of(
                "className", className,
                "rows", rows
        );

        try (final Writer out = Files.newBufferedWriter(
                outputDir.resolve("classes").resolve(fileName(className)))) {
            Fm.render("class.ftl", model, out);
        }
    }

    /**
     * Counts the number of analyses with the specified verdict.
     *
     * @param v the verdict to count
     * @return the count of analyses with the verdict
     */
    private long count(final Verdict v)
    {
        return byClass.values().stream().flatMap(List::stream).filter(a -> a.verdict() == v)
                .count();
    }

    /**
     * Copies static resources (e.g., CSS and JS) to the output directory.
     *
     * @throws IOException if an I/O error occurs
     */
    private void copyStatic() throws IOException
    {
        final Path dest = outputDir.resolve("resources");
        Files.createDirectories(dest);
        copyResource("/report-template/style.css", dest.resolve("style.css"));
        copyResource("/report-template/report.js", dest.resolve("report.js"));
    }
}
