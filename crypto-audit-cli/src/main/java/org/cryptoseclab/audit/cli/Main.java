/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.cli;

import org.cryptoseclab.audit.fips.FipsPolicyEngine;
import org.cryptoseclab.audit.jce.catalog.Catalog;
import org.cryptoseclab.audit.jce.catalog.CatalogYamlLoader;
import org.cryptoseclab.audit.jce.sootup.SootUpScanner;
import org.cryptoseclab.audit.policy.Analysis;
import org.cryptoseclab.audit.policy.Policy;
import org.cryptoseclab.audit.policy.PolicyEngine;
import org.cryptoseclab.audit.policy.PolicyYamlLoader;
import org.cryptoseclab.audit.report.HtmlReportWriter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(
        name = "crypto-audit",
        mixinStandardHelpOptions = true,
        version = "crypto-audit 1.0",
        description = "Scans classes/JARs for JCE usage and evaluates against a policy."
)
public class Main implements Callable<Integer>
{
    @Option(
            names = "--input",
            required = true,
            description = "Path to classes directory or JAR to scan"
    )
    private Path input;

    @Option(
            names = "--catalog",
            description = "Path to catalog YAML; if omitted, loads crypto-catalog.yaml from classpath"
    )
    private Path catalogPath;

    @Option(
            names = "--policy",
            description = "Path to policy YAML; if omitted, loads policy-fips.yaml from classpath"
    )
    private Path policyPath;

    @Option(
            names = "--format",
            description = "Output format: ${COMPLETION-CANDIDATES}",
            defaultValue = "html"
    )
    private OutputFormat format;

    @Option(
            names = "--verbose",
            description = "Verbose logging"
    )
    private boolean verbose;

    public static void main(String[] args)
    {
        int code = new CommandLine(new Main()).execute(args);
        System.exit(code);
    }

    @Override
    public Integer call() throws Exception
    {
        final var catalogLoader = new CatalogYamlLoader();
        final Catalog catalog = catalogPath == null
                ? catalogLoader.loadDefaultCatalog()
                : catalogLoader.loadCatalog(catalogPath);

        final var policyLoader = new PolicyYamlLoader();
        final Policy policy = policyPath == null
                ? policyLoader.loadDefaultPolicy()
                : policyLoader.loadPolicy(policyPath);

        if (verbose) {
            System.out.printf("Catalog: %s (%d apis)%n", catalog.catalogId(),
                    catalog.apis().size());
            System.out.printf("Policy : %s (%d rules)%n", policy.policyId(), policy.rules().size());
            System.out.printf("Input  : %s%n", input);
        }

        final var findingsMap = new SootUpScanner(catalog).scan(input);
        final PolicyEngine engine = new FipsPolicyEngine(catalog);
        final var analysisResultsMap = findingsMap.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().stream()
                                .map(f -> engine.evaluate(f, policy))
                                .toList()
                ));

        switch (format) {
            case text -> {
                for (final var entry : analysisResultsMap.entrySet()) {
                    System.out.printf("Class: %s%n", entry.getKey());
                    printText(entry.getValue());
                }
            }
            case html -> {
                final var outputDir = input.getParent().resolve("reports");
                final var reportWriter = new HtmlReportWriter(analysisResultsMap, outputDir);
                System.out.println("Writing HTML report to " + outputDir);
                reportWriter.write();
            }
        }
        return 0;
    }

    private void printText(final List<Analysis> results)
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

    enum OutputFormat {text, html}
}
