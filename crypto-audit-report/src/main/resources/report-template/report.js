/*
 * Copyright (c) 2025 Crypto Security Labs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

(function () {
    function applyFilters() {
        const checks = Array.from(document.querySelectorAll('.filters input[type=checkbox]'));
        const allowed = new Set(checks.filter(c => c.checked).map(c => c.getAttribute('data-verdict')));

        const rows = document.querySelectorAll('#findings tbody tr');
        rows.forEach(row => {
            // row has class like "row-PASS", "row-FAIL", "row-UNKNOWN"
            const v = Array.from(row.classList)
                .map(c => c.startsWith('row-') ? c.substring(4) : null)
                .find(Boolean);
            row.style.display = allowed.has(v) ? '' : 'none';
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.filters input[type=checkbox]')
            .forEach(cb => cb.addEventListener('change', applyFilters));
        applyFilters();
    });
})();
