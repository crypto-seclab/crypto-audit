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
    <title>Crypto Analysis Report</title>
    <link rel="stylesheet" href="resources/style.css"/>
</head>
<body>
<h1>Crypto Analysis Report</h1>

<div class="summary">
    <div class="card">Total: <b>${summary.total}</b></div>
    <div class="card verdict-PASS">PASS: <b>${summary.pass}</b></div>
    <div class="card verdict-FAIL">FAIL: <b>${summary.fail}</b></div>
    <div class="card verdict-UNKNOWN">UNKNOWN: <b>${summary.unknown}</b></div>
</div>

<h2>Classes with issues</h2>
<#if issueClasses?size == 0>
    <p>None 🎉</p>
<#else>
    <table>
        <thead>
        <tr>
            <th>Class</th>
            <th>Total</th>
            <th>PASS</th>
            <th>FAIL</th>
            <th>UNKNOWN</th>
        </tr>
        </thead>
        <tbody>
        <#list issueClasses as c>
            <tr>
                <td><a href="classes/${c.fileName}">${c.className}</a></td>
                <td>${c.total}</td>
                <td class="verdict-PASS">${c.pass}</td>
                <td class="verdict-FAIL">${c.fail}</td>
                <td class="verdict-UNKNOWN">${c.unknown}</td>
            </tr>
        </#list>
        </tbody>
    </table>
</#if>

<h2>Classes with no issues</h2>
<#if cleanClasses?size == 0>
    <p>None.</p>
<#else>
    <table>
        <thead>
        <tr>
            <th>Class</th>
            <th>Total</th>
            <th>PASS</th>
            <th>FAIL</th>
            <th>UNKNOWN</th>
        </tr>
        </thead>
        <tbody>
        <#list cleanClasses as c>
            <tr>
                <td>${c.className}</td>  <!-- plain text, not clickable -->
                <td>${c.total}</td>
                <td class="verdict-PASS">${c.pass}</td>
                <td class="verdict-FAIL">${c.fail}</td>
                <td class="verdict-UNKNOWN">${c.unknown}</td>
            </tr>
        </#list>
        </tbody>
    </table>
</#if>
</body>
</html>
