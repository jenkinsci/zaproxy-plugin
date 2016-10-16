/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 mabdelmoez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.github.jenkinsci.zaproxyplugin;

import java.io.Serializable;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

/**
 * This object allows to add a script parameters dynamically.
 *
 * @author mabdelmoez
 *
 */
public class ZAPAuthScriptParam extends AbstractDescribableImpl<ZAPAuthScriptParam> implements Serializable {

    private static final long serialVersionUID = -6217726623494939211L;

    /** Configuration key for the command line */
    private final String scriptParameterName;

    /** Configuration value for the command line */
    private final String scriptParameterValue;

    @DataBoundConstructor
    public ZAPAuthScriptParam(String scriptParameterName, String scriptParameterValue) {
        this.scriptParameterName = scriptParameterName;
        this.scriptParameterValue = scriptParameterValue;
    }

    public String getScriptParameterName() { return scriptParameterName; }

    public String getScriptParameterValue() { return scriptParameterValue; }

    @Extension
    public static class ZAPauthScriptParamDescriptorImpl extends Descriptor<ZAPAuthScriptParam> {

        @Override
        public String getDisplayName() { return "Authentication Script Parameter"; }
    }
}
