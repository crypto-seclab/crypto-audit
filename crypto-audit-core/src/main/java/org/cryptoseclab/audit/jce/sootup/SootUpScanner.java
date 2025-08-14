/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.cryptoseclab.audit.jce.sootup;

import lombok.extern.slf4j.Slf4j;
import org.cryptoseclab.audit.jce.catalog.ArgSpec;
import org.cryptoseclab.audit.jce.catalog.Catalog;
import org.cryptoseclab.audit.jce.scan.ArgumentValue;
import org.cryptoseclab.audit.jce.scan.ByteCodeScanner;
import org.cryptoseclab.audit.jce.scan.Finding;
import org.cryptoseclab.audit.jce.scan.Location;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Scans Java bytecode for cryptographic API usage using SootUp.
 * Implements the {@link ByteCodeScanner} interface.
 */
@Slf4j
public class SootUpScanner implements ByteCodeScanner
{
    private final Map<String, ArgSpec> jceApis;
    private final Catalog catalog;

    /**
     * Constructs a new SootUpScanner instance.
     *
     * @param catalog the {@link Catalog} containing cryptographic API specifications
     */
    public SootUpScanner(final Catalog catalog)
    {
        this.catalog = catalog;
        jceApis = this.catalog.argSpecByApi();
    }

    /**
     * Scans the specified input file or directory for Java bytecode and identifies findings.
     *
     * @param input the {@link Path} to the file or directory to scan
     * @return a map where the keys are class names and the values are lists of {@link Finding} objects
     * representing cryptographic call sites discovered during the scan
     * @throws IOException if an I/O error occurs while reading the input
     */
    @Override
    public Map<String, List<Finding>> scan(final Path input) throws IOException
    {
        final var javaView = new JavaView(
                new JavaClassPathAnalysisInputLocation(input.toString()));
        final var findingsMap = new TreeMap<String, List<Finding>>();

        javaView.getClasses().parallel().forEach(sootClass -> {
            log.info("Scanning class: {}", sootClass.getName());
            final var findings = new ArrayList<Finding>();
            sootClass.getMethods().stream().parallel().forEach(sootMethod -> {
                if (!(sootMethod instanceof JavaSootMethod jm) || !jm.hasBody()) return;
                log.debug("Scanning method: {}", sootMethod.getName());

                final var stmts = jm.getBody().getStmts();
                for (final Stmt stmt : stmts) {
                    if (!stmt.isInvokableStmt()) continue;
                    final var opt = stmt.asInvokableStmt().getInvokeExpr();
                    if (opt.isEmpty()) continue;

                    final AbstractInvokeExpr invoke = opt.get();
                    final var subSignature = invoke.getMethodSignature().getSubSignature();

                    final String declClass = subSignature.getType().toString();
                    final String methodName = subSignature.getName();
                    final ArgSpec argSpec = jceApis.get(catalog.key(declClass, methodName));
                    if (argSpec == null) continue; // not in catalog

                    log.debug("Found crypto call: {}", catalog.key(declClass, methodName));

                    // 3) Capture args (both printable and literal if resolved)
                    final var args = new ArrayList<ArgumentValue>();
                    for (int i = 0; i < invoke.getArgCount(); i++) {
                        final var immediate = invoke.getArg(i);

                        final boolean isLiteral = immediate instanceof StringConstant;
                        final String literal = isLiteral
                                ? ((StringConstant) immediate).getValue()
                                : immediate.toString();

                        args.add(ArgumentValue.builder()
                                .index(i)
                                .printable(literal)
                                .literalOrNull(isLiteral ? literal : null)
                                .build());
                    }

                    // 4) Location from statement position info
                    final int line = stmt.getPositionInfo().getStmtPosition().getFirstLine();
                    var loc = Location.builder()
                            .className(sootClass.getName())
                            .methodSignature(sootMethod.getSubSignature().toString())
                            .sourceFile(sootClass.getName()) // can be refined later
                            .line(line)
                            .build();

                    // 5) Emit finding
                    final String api = declClass + "." + methodName;
                    findings.add(Finding.builder()
                            .api(api)
                            .declaringClass(declClass)
                            .methodName(methodName)
                            .subSignature(subSignature.toString())
                            .args(args)
                            .location(loc)
                            .build());
                }
            });
            findingsMap.put(sootClass.getName(), findings);
            log.info("Finished scanning class: {}", sootClass.getName());
        });

        return findingsMap;
    }
}
