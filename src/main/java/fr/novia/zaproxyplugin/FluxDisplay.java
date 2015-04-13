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

import hudson.model.BuildListener;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Classe qui permet d'afficher les sorties (standard, d'erreur, ...)
 * d'une application externe.
 * 
 * @author ludovic.roucoux
 *
 */
public class FluxDisplay implements Runnable {
	
	private final InputStream inputStream;
	private final BuildListener listener;
	
	public FluxDisplay(InputStream is, BuildListener listener) {
		this.inputStream = is;
		this.listener = listener;
	}
	
	private BufferedReader getBufferedReader(InputStream is) {
		return new BufferedReader(new InputStreamReader(is));
	}

	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {
		try {
			BufferedReader br = getBufferedReader(inputStream);
			String line = "";
			try {
				while ((line = br.readLine()) != null) {
					listener.getLogger().println(line);
				}
			} finally {
				br.close();
			}
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
