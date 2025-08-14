<!--
  Copyright (c) Crypto Security Labs

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

  SPDX-License-Identifier: MPL-2.0
-->

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <title>${className}</title>
    <link rel="stylesheet" href="../resources/style.css"/>
    <script defer src="../resources/report.js"></script>
</head>
<body>
<div class="breadcrumbs"><a href="../index.html">&larr; Summary</a></div>
<h2>${className}</h2>

<div class="filters">
    <label><input type="checkbox" data-verdict="PASS" checked> PASS</label>
    <label><input type="checkbox" data-verdict="FAIL" checked> FAIL</label>
    <label><input type="checkbox" data-verdict="UNKNOWN" checked> UNKNOWN</label>
</div>

<table id="findings">
    <thead>
    <tr>
        <th>Line</th>
        <th>Method</th>
        <th>API</th>
        <th>Algorithm</th>
        <th>Provider</th>
        <th>Verdict</th>
        <th>Reason</th>
        <th>Policy</th>
    </tr>
    </thead>
    <tbody>
    <#list rows as r>
        <tr class="row-${r.verdict}">
            <td>${r.line}</td>
            <td>${r.method}</td>
            <td>${r.api}</td>
            <td>${r.algo}</td>
            <td>${r.prov}</td>
            <td class="verdict-${r.verdict}">${r.verdict}</td>
            <td>${r.reason!""}</td>
            <td>${r.policy!""}</td>
        </tr>
    </#list>
    </tbody>
</table>
</body>
</html>
