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

package fr.novia.zaproxyplugin;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * This object allows to override a ZAP default config (OWASP ZAP/config.xml)
 * using "-config" with key/value pair.
 * @see <a href="https://code.google.com/p/zaproxy/wiki/HelpCmdline">
 * 		https://code.google.com/p/zaproxy/wiki/HelpCmdline</a>
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAPconfig extends AbstractDescribableImpl<ZAPconfig>{
	private final String key;
	private final String value;

	@DataBoundConstructor 
	public ZAPconfig(String key, String value) {
		this.key = key;
		this.value = value;
	}

	public String getKey() {
		return key;
	}

	public String getValue() {
		return value;
	}
	
	public boolean isFilled() {
		if(!key.isEmpty() && key != null && !value.isEmpty() && value != null) {
			return true;
		}
		return false;
	}

	@Extension 
	public static class ZAPconfigDescriptorImpl extends Descriptor<ZAPconfig> {
		@Override public String getDisplayName() {
			return "ZAP config";
		}
	}
}
