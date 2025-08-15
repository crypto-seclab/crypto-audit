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

import lombok.Builder;

/**
 * Represents a cryptographic rule that defines constraints for APIs, algorithms, and providers.
 *
 * @param id         the unique identifier for the rule, must not be null
 * @param api        the fully qualified API name (e.g., java.security.MessageDigest.getInstance), must not be null
 * @param algorithms the {@link Algorithms} object specifying allowed algorithm names, may be null
 * @param providers  the {@link Providers} object specifying allowed or denied providers, may be null
 */
@Builder(toBuilder = true)
public record Rule(
        String id,
        String description,
        String api,
        Algorithms algorithms,
        Providers providers
)
{
}
