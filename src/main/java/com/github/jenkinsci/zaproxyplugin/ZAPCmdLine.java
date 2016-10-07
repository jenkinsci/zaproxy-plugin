/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 ludovicRoucoux
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

package com.github.jenkinsci.zaproxyplugin;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

/**
 * This object allows to add a ZAP command line option.
 * 
 * @see <a href="https://code.google.com/p/zaproxy/wiki/HelpCmdline">
 * 		https://code.google.com/p/zaproxy/wiki/HelpCmdline</a>
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAPCmdLine extends AbstractDescribableImpl<ZAPCmdLine> implements Serializable {
	private static final long serialVersionUID = -695679474175608775L;

	/** Configuration key for the command line */
	private final String cmdLineOption;
	
	/** Configuration value for the command line */
	private final String cmdLineValue;

	@DataBoundConstructor 
	public ZAPCmdLine(String cmdLineOption, String cmdLineValue) {
		this.cmdLineOption = cmdLineOption;
		this.cmdLineValue = cmdLineValue;
	}

	public String getCmdLineOption() {
		return cmdLineOption;
	}

	public String getCmdLineValue() {
		return cmdLineValue;
	}
	
	@Extension 
	public static class ZAPcmdLineDescriptorImpl extends Descriptor<ZAPCmdLine> {
		@Override 
		public String getDisplayName() {
			return "ZAP command Line";
		}
	}

}
