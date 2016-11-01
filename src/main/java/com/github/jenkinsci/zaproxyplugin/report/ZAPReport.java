/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Official ZAP Jenkins Plugin and its related class files.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.github.jenkinsci.zaproxyplugin.report;

import java.io.Serializable;

import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

/**
 * This abstract class is used to generate report in ZAP available format.
 *
 * @author ludovic.roucoux
 *
 */
public abstract class ZAPReport implements Serializable {

    private static final long serialVersionUID = 2241940678203529066L;

    protected static final String REPORT_FORMAT_XML = "xml";
    protected static final String REPORT_FORMAT_HTML = "html";

    /** The report format */
    protected String format;

    /**
     * Generate a ZAP report in the format of daughter class.
     *
     * @param clientApi
     *            the ZAP api to call the method to generate report
     * @param apikey
     *            ZAP apikey. Can be null.
     * @return an array of byte containing the report.
     * @throws ClientApiException
     */
    public abstract byte[] generateReport(ClientApi clientApi, String apikey) throws ClientApiException;

    public String getFormat() { return format; }

    @Override
    public String toString() { return getFormat(); }
}
