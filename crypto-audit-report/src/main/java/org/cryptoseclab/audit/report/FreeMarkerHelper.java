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

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.Version;

import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

final class FreeMarkerHelper
{
    private final Configuration configuration;


    public FreeMarkerHelper()
    {
        configuration = new Configuration(new Version("2.3.34"));
        configuration.setClassLoaderForTemplateLoading(
                Thread.currentThread().getContextClassLoader(), "/report-template");
        configuration.setDefaultEncoding(StandardCharsets.UTF_8.name());
    }

    public void render(String templateName, Map<String, Object> model, Writer out) throws Exception
    {
        Template t = configuration.getTemplate(templateName);
        t.process(model, out);
    }
}

