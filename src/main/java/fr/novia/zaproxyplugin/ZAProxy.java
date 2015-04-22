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

import hudson.EnvVars;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.BuildListener;
import hudson.model.EnvironmentSpecific;
import hudson.model.AbstractBuild;
import hudson.model.Descriptor;
import hudson.model.Node;
import hudson.slaves.NodeSpecific;
import hudson.slaves.SlaveComputer;
import hudson.tools.ToolDescriptor;
import hudson.tools.ToolInstallation;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.tools.ant.BuildException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import javax.servlet.ServletException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Contains methods to start and execute ZAProxy.
 * Members variables are bind to the config.jelly placed to fr/novia/zaproxyplugin/ZAProxy
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAProxy extends AbstractDescribableImpl<ZAProxy> {

	private static final String API_KEY = "ZAPROXY-PLUGIN";
	public static final String ALL_REPORT_FORMAT = "all";
	private static final int MILLISECONDS_IN_SECOND = 1000;
	private static final String FILE_POLICY_EXTENSION = ".policy";
	private static final String NAME_POLICIES_DIR_ZAP = "policies";
	
	/** Host configured when ZAProxy is used as proxy */
	private String zapProxyHost;
	
	/** Port configured when ZAProxy is used as proxy */
	private int zapProxyPort;
	
	/** Allows to use the ZAProxy client API */
	private ClientApi zapClientAPI;
	
	/** Path to the ZAProxy program */
	private String zapProgram;
	
	/** Indicate if ZAProxy is automatically installed by Jenkins or if it is already install on the machine */
	private final boolean autoInstall;
	
	/** The ZAproxy tool to use */
	private final String toolUsed;
	
	/** Environment variable about ZAProxy path */
	private final String zapHome;
	
	/** Time total to wait for zap initialization. After this time, the program is stopped */
	private final int timeoutInSec;

	/** Filename to load ZAProxy session. It can contain a relative path */
	private final String filenameLoadSession;
	
	/** URL to attack by ZAProxy */
	private final String targetURL;
	
	/** Realize a url spider or not by ZAProxy */
	private final boolean spiderURL;
	
	/** Realize a url scan or not by ZAProxy */
	private final boolean scanURL;
	
	/** Save reports or not */
	private final boolean saveReports;

	/** Chosen format for reports */
	private final String chosenFormat;
	
	/** Filename for ZAProxy reports. It can contain a relative path. */
	private final String filenameReports;
	
	/** Save session or not */
	private final boolean saveSession;
	
	/** Filename to save ZAProxy session. It can contain a relative path. */
	private final String filenameSaveSession;
	
	/** The default directory that ZAP uses */
	private final String zapDefaultDir;
	
	/** The file policy to use for the scan. It contains only the policy name (without extension) */
	private final String chosenPolicy;
	
	
	// Fields in fr/novia/zaproxyplugin/ZAProxy/config.jelly must match the parameter names in the "DataBoundConstructor"
	@DataBoundConstructor
	public ZAProxy(boolean autoInstall, String toolUsed, String zapHome, int timeoutInSec,
			String filenameLoadSession, String targetURL, boolean spiderURL, boolean scanURL,
			boolean saveReports, String chosenFormat, String filenameReports,
			boolean saveSession, String filenameSaveSession,
			String zapDefaultDir, String chosenPolicy) {
		
		

		this.autoInstall = autoInstall;
		this.toolUsed = toolUsed;
		this.zapHome = zapHome;
		this.timeoutInSec = timeoutInSec;
		this.filenameLoadSession = filenameLoadSession;
		this.targetURL = targetURL;
		this.spiderURL = spiderURL;
		this.scanURL = scanURL;
		this.saveReports = saveReports;
		this.chosenFormat = chosenFormat;
		this.filenameReports = filenameReports;
		this.saveSession = saveSession;
		this.filenameSaveSession = filenameSaveSession;
		this.zapDefaultDir = zapDefaultDir;
		this.chosenPolicy = chosenPolicy;
	}
	
	@Override
	public String toString() {
		String s = "";
		s += "autoInstall ["+autoInstall+"]\n";
		s += "toolUsed ["+toolUsed+"]\n";
		s += "zapHome ["+zapHome+"]\n";
		s += "timeoutInSec ["+timeoutInSec+"]\n";
		s += "filenameLoadSession ["+filenameLoadSession+"]\n";
		s += "targetURL ["+targetURL+"]\n";
		s += "spiderURL ["+spiderURL+"]\n";
		s += "scanURL ["+scanURL+"]\n";
		s += "saveReports ["+saveReports+"]\n";
		s += "chosenFormat ["+chosenFormat+"]\n";
		s += "filenameReports ["+filenameReports+"]\n";
		s += "saveSession ["+saveSession+"]\n";
		s += "filenameSaveSession ["+filenameSaveSession+"]\n";
		s += "zapDefaultDir ["+zapDefaultDir+"]\n";
		s += "chosenPolicy ["+chosenPolicy+"]\n";
		
		s += "zapProxyHost ["+zapProxyHost+"]\n";
		s += "zapProxyPort ["+zapProxyPort+"]\n";
		
		return s;
	}
	
	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyDescriptorImpl getDescriptor() {
		return (ZAProxyDescriptorImpl)super.getDescriptor();
	}
	
	/*
	 * Getters allows to load members variables into UI.
	 */
	public boolean getAutoInstall() {
		return autoInstall;
	}

	public String getToolUsed() {
		return toolUsed;
	}

	public String getZapHome() {
		return zapHome;
	}

	public int getTimeoutInSec() {
		return timeoutInSec;
	}

	public String getFilenameLoadSession() {
		return filenameLoadSession;
	}

	public String getTargetURL() {
		return targetURL;
	}

	public boolean getSpiderURL() {
		return spiderURL;
	}

	public boolean getScanURL() {
		return scanURL;
	}

	public boolean getSaveReports() {
		return saveReports;
	}

	public String getChosenFormat() {
		return chosenFormat;
	}

	public String getFilenameReports() {
		return filenameReports;
	}

	public boolean getSaveSession() {
		return saveSession;
	}

	public String getFilenameSaveSession() {
		return filenameSaveSession;
	}

	public String getZapDefaultDir() {
		return zapDefaultDir;
	}
	
	public String getChosenPolicy() {
		return chosenPolicy;
	}

	public void setZapProxyHost(String zapProxyHost) {
		this.zapProxyHost = zapProxyHost;
	}

	public void setZapProxyPort(int zapProxyPort) {
		this.zapProxyPort = zapProxyPort;
	}

	/**
	 * Get the ZAP_HOME setup by Custom Tools Plugin or already present on the machine. 
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @return the installed tool location, without zap.bat or zap.sh at the end
	 * @see <a href="https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk">
	 * 	https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk</a>
	 */
	private String retrieveZapHomeWithToolInstall(AbstractBuild<?, ?> build, BuildListener listener) {	
		
		EnvVars env = null;
		Node node = null;
		String installPath = null;
		
		try {	
			if(autoInstall) {
				env = build.getEnvironment(listener);
				node = build.getBuiltOn();
				for (ToolDescriptor<?> desc : ToolInstallation.all()) {
					for (ToolInstallation tool : desc.getInstallations()) {
						if (tool.getName().equals(toolUsed)) {
							if (tool instanceof NodeSpecific) {
								tool = (ToolInstallation) ((NodeSpecific<?>) tool).forNode(node, listener);
							}
							if (tool instanceof EnvironmentSpecific) {
								tool = (ToolInstallation) ((EnvironmentSpecific<?>) tool).forEnvironment(env);
							}
							installPath = tool.getHome();
							
							return installPath;
						}
					}
				}
			} else {
				installPath = build.getEnvironment(listener).get(zapHome);
			}
		} catch (Exception e) {
			e.printStackTrace();
			listener.error(e.toString());
		}
		return installPath;
	}
	
	/**
	 * Return the ZAProxy program name (zap.bat or zap.sh) depending of the build node and the OS.
	 * 
	 * @param build
	 * @return the ZAProxy program name (zap.bat or zap.sh)
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private String getZAPProgramName(AbstractBuild<?, ?> build) throws IOException, InterruptedException {
		Node node = build.getBuiltOn();
		String zapProgramName = "";
		
		// Append zap program following Master/Slave and Windows/Unix
		if( node.getNodeName().equals("")) { // Master
			if( File.pathSeparatorChar == ':' ) { // UNIX
				zapProgramName = "zap.sh";
			} else { // Windows (pathSeparatorChar == ';')
				zapProgramName = "zap.bat";
			}
		} 
		else { // Slave
			if( ((SlaveComputer)node.toComputer()).getOSDescription().equals("Unix") ) {
				zapProgramName = "zap.sh";
			} else {
				zapProgramName = "zap.bat";
			}
		}
		return zapProgramName;
	}
	
	/**
	 * Verify parameters of the build setup are correct (null, empty, negative ...)
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws Exception throw an exception if a parameter is invalid.
	 */
	private void checkParams(AbstractBuild<?, ?> build, BuildListener listener) throws Exception {
		zapProgram = retrieveZapHomeWithToolInstall(build, listener);
		
		if(zapProgram.isEmpty() || zapProgram == null) {
			throw new Exception("zapProgram is missing");
		} else
			listener.getLogger().println("zapProgram = " + zapProgram);
		
		if(targetURL.isEmpty() || targetURL == null) {
			throw new Exception("targetURL is missing");
		} else
			listener.getLogger().println("targetURL = " + targetURL);

		if(zapProxyHost.isEmpty() || zapProxyHost == null) {
			throw new Exception("zapProxy Host is missing");
		} else
			listener.getLogger().println("zapProxyHost = " + zapProxyHost);

		if(zapProxyPort < 0) {
			throw new Exception("zapProxy Port is less than 0");
		} else
			listener.getLogger().println("zapProxyPort = " + zapProxyPort);
		
	}
	
	/**
	 * Start ZAProxy using command line. It uses host and port configured in Jenkins admin mode and
	 * ZAProxy program is launched in daemon mode (i.e without UI).
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws Exception 
	 */
	public void startZAP(AbstractBuild<?, ?> build, BuildListener listener) throws Exception {
		checkParams(build, listener);
		
		File zapProgramFile = new File(zapProgram, getZAPProgramName(build));
		
		listener.getLogger().println("Start ZAProxy [" + zapProgramFile.getAbsolutePath() + "]");
		
		// Command to start ZAProxy with parameters
		List<String> cmd = new ArrayList<String>();
		cmd.add(zapProgramFile.getAbsolutePath()); 
		cmd.add("-daemon");
		cmd.add("-host"); cmd.add(zapProxyHost);
		cmd.add("-port"); cmd.add(String.valueOf(zapProxyPort));
		
		// Set the default directory used by ZAP if it's defined
		if(!zapDefaultDir.equals("") && zapDefaultDir != null) {
			cmd.add("-dir"); cmd.add(zapDefaultDir);
		}
		
		ProcessBuilder pb = new ProcessBuilder(cmd);
		pb.directory(zapProgramFile.getParentFile());
		
		Process p = pb.start();
		
		FluxDisplay outputFlux = new FluxDisplay(p.getInputStream(), listener);
		FluxDisplay errorFlux = new FluxDisplay(p.getErrorStream(), listener);
		new Thread(outputFlux).start();
		new Thread(errorFlux).start();
		
		waitForSuccessfulConnectionToZap(timeoutInSec, listener);
	}
	
	/**
	 * Wait for ZAProxy initialization, so it's ready to use at the end of this method
	 * (otherwise, catch exception).
	 *   
	 * @param timeout the time in sec to try to connect at zap proxy. 
	 * @param listener the listener to display log during the job execution in jenkins
	 * @see <a href="https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
	 * 		https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960</a>
	 */
	private void waitForSuccessfulConnectionToZap(int timeout, BuildListener listener) {
		int timeoutInMs = getMilliseconds(timeout);
		int connectionTimeoutInMs = timeoutInMs;
		int pollingIntervalInMs = getMilliseconds(1);
		boolean connectionSuccessful = false;
		long startTime = System.currentTimeMillis();
		Socket socket = null;
		do {
			try {
				socket = new Socket();
				socket.connect(new InetSocketAddress(zapProxyHost, zapProxyPort), connectionTimeoutInMs);
				connectionSuccessful = true;
			} catch (SocketTimeoutException ignore) {
				throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
			} catch (IOException ignore) {
				// and keep trying but wait some time first...
				try {
					Thread.sleep(pollingIntervalInMs);
				} catch (InterruptedException e) {
					throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
				}

				long ellapsedTime = System.currentTimeMillis() - startTime;
				if (ellapsedTime >= timeoutInMs) {
					throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
				}
				connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
			} finally {
				if(socket != null) {
					try {
						socket.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		} while (!connectionSuccessful);
	}
	
	/**
	 * Converts seconds in milliseconds.
	 * @param seconds the time in second to convert
	 * @return the time in milliseconds
	 */
	private static int getMilliseconds(int seconds) {
		return seconds * MILLISECONDS_IN_SECOND;
	}
	
	/**
	 * Get all security alerts raised by ZAProxy
	 *
	 * @param format the report format file
	 * @param listener the listener to display log during the job execution in jenkins
	 * @return all alerts from ZAProxy in a string
	 * @throws Exception
	 */
	private String getAllAlerts(final String format, BuildListener listener) throws Exception {
		URL url;
		String result = "";
		Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(zapProxyHost, zapProxyPort));
		
		url = new URL("http://zap/" + format + "/core/view/alerts");

		listener.getLogger().println("Open URL: " + url.toString());

		final HttpURLConnection uc = (HttpURLConnection) url.openConnection(proxy);
		uc.connect();

		final BufferedReader in = new BufferedReader(new InputStreamReader(
				uc.getInputStream()));
		String inputLine;

		while ((inputLine = in.readLine()) != null) {
			result = result + inputLine;
		}

		in.close();
		return result;
	}
	
	/**
	 * Save security alerts into a file
	 * @param format the report format (xml, html or json)
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws Exception
	 */
	private void saveReport(final String format, BuildListener listener, AbstractBuild<?, ?> build) throws Exception {
		final String alerts = getAllAlerts(format, listener);
		final String fullFileName = filenameReports + "." + format;
		File reportsFile = new File(build.getWorkspace().getRemote(), fullFileName);
		FileUtils.writeStringToFile(reportsFile, alerts);
		listener.getLogger().println("File ["+ reportsFile.getAbsolutePath() +"] saved");
	}

	/**
	 * Execute ZAProxy method following build's setup.
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws Exception
	 */
	public void executeZAP(AbstractBuild<?, ?> build, BuildListener listener) throws Exception {
		zapClientAPI = new ClientApi(zapProxyHost, zapProxyPort);
		
		/* ======================================================= 
		 * |                  LOAD SESSION                        |
		 * ======================================================= 
		 */
		if(filenameLoadSession != null && filenameLoadSession.length() != 0) {
			File sessionFile = new File(build.getWorkspace().getRemote(), filenameLoadSession);
			listener.getLogger().println("Load session at ["+ sessionFile.getAbsolutePath() +"]");
			zapClientAPI.core.loadSession(API_KEY, sessionFile.getAbsolutePath());
		} else {
			listener.getLogger().println("Skip loadSession");
		}
		
		/* ======================================================= 
		 * |                  SPIDER URL                          |
		 * ======================================================= 
		 */
		if (spiderURL) {
			listener.getLogger().println("Spider the site [" + targetURL + "]");
			spiderURL(targetURL, listener);
		} else {
			listener.getLogger().println("Skip spidering the site [" + targetURL + "]");
		}

		/* ======================================================= 
		 * |                  SCAN URL                            |
		 * ======================================================= 
		 */
		if (scanURL) {				
			listener.getLogger().println("Scan the site [" + targetURL + "]");
			scanURL(targetURL, listener);
		} else {
			listener.getLogger().println("Skip scanning the site [" + targetURL + "]");
		}
		
		/* ======================================================= 
		 * |                  SAVE REPORTS                        |
		 * ======================================================= 
		 */
		if (saveReports) {
			if(chosenFormat.equalsIgnoreCase(ZAProxy.ALL_REPORT_FORMAT)) {
				listener.getLogger().println("Generate reports in all formats");
				
				// Loop of all available formats ("all" format included)
				for(String format : getDescriptor().getFormatList()) {
					if(!format.equals(ZAProxy.ALL_REPORT_FORMAT)) {
						saveReport(format, listener, build);
					}
				}
			} else {
				saveReport(chosenFormat, listener, build);
			}
		}
		
		/* ======================================================= 
		 * |                  SAVE SESSION                        |
		 * ======================================================= 
		 */
		if(saveSession) {
			if(filenameSaveSession != null && !filenameSaveSession.isEmpty()) {
				File sessionFile = new File(build.getWorkspace().getRemote(), filenameSaveSession);
				listener.getLogger().println("Save session to ["+ sessionFile.getAbsolutePath() +"]");
				
				// Path creation if it doesn't exist
				if(!sessionFile.getParentFile().exists()) {
					sessionFile.getParentFile().mkdirs();
				}
				
				// Method signature : saveSession(String apikey, String name, String overwrite)
				zapClientAPI.core.saveSession(API_KEY, sessionFile.getAbsolutePath(), "true");
			} 
		} else {
			listener.getLogger().println("Skip saveSession");
		}
		
		listener.getLogger().println("Nb alertes = " + zapClientAPI.core.numberOfAlerts("").toString(2));
		listener.getLogger().println("Nb msg = " + zapClientAPI.core.numberOfMessages("").toString(2));
	}
	
	/**
	 * Converts the ZAP API status response to an integer
	 *
	 * @param response the ZAP API response code
	 * @return the integer status of the ApiResponse
	 */
	private int statusToInt(final ApiResponse response) {
		return Integer.parseInt(((ApiResponseElement)response).getValue());
	}
	
	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 *
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void spiderURL(final String url, BuildListener listener) throws ClientApiException, InterruptedException {
		// Method signature : scan(String key, String url, String maxChildren)
		zapClientAPI.spider.scan(API_KEY, url, "");

		// Wait for complete spidering (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.spider.status("")) < 100) {
			listener.getLogger().println("status spider = " + statusToInt(zapClientAPI.spider.status("")));
			listener.getLogger().println("Nb alertes = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			Thread.sleep(1000);
		}
	}
	
	/**
	 * Scan all pages found at url and raised actives alerts
	 *
	 * @param url the url to scan
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void scanURL(final String url, BuildListener listener) throws ClientApiException, InterruptedException {
		// Method signature : scan(String apikey, String url, String recurse, String inscopeonly, String scanpolicyname, String method, String postdata)
		// Use a default policy if chosenPolicy is null or empty
		zapClientAPI.ascan.scan(API_KEY, url, "true", "false", chosenPolicy, null, null);

		// Wait for complete scanning (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.ascan.status("")) < 100) {
			listener.getLogger().println("status scan = " + statusToInt(zapClientAPI.ascan.status("")));
			listener.getLogger().println("Nb alertes = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			listener.getLogger().println("Nb msg url = " + zapClientAPI.core.numberOfMessages("").toString(2));
			Thread.sleep(5000);
		}
	}
	
	/**
	 * Stop ZAproxy if it has been previously started.
	 * 
	 * @param listener the listener to display log during the job execution in jenkins
	 */
	public void stopZAP(BuildListener listener) {
		if (zapClientAPI != null) {
			try {
				listener.getLogger().println("Shutdown ZAProxy");
				zapClientAPI.core.shutdown(API_KEY);
			} catch (final Exception e) {
				listener.error(e.toString());
				e.printStackTrace();
			}
		} else {
			listener.getLogger().println("No shutdown of ZAP (zapClientAPI==null)");
		}
	}
	
	
	/**
	 * Descriptor for {@link ZAProxy}. Used as a singleton.
	 * The class is marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See <tt>src/main/resources/fr/novia/zaproxyplugin/ZAProxy/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension
	public static class ZAProxyDescriptorImpl extends Descriptor<ZAProxy> {
		/**
		 * To persist global configuration information,
		 * simply store it in a field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		private List<String> formatList;
		
		/**
		 * In order to load the persisted global configuration, you have to
		 * call load() in the constructor.
		 */
		public ZAProxyDescriptorImpl() {
			formatList = new ArrayList<String>();
			formatList.add("xml");		
			formatList.add("json");		
			formatList.add("html");		
			formatList.add(ZAProxy.ALL_REPORT_FORMAT);
			load();
		}
		
		@Override
		public String getDisplayName() { 
			return null; 
		}

		public List<String> getFormatList() {
			return formatList;
		}
		
		/**
		 * Performs on-the-fly validation of the form field 'filenameReports'.
		 *
		 * @param filenameReports
		 *      This parameter receives the value that the user has typed.
		 * @return
		 *      Indicates the outcome of the validation. This is sent to the browser.
		 *      <p>
		 *      Note that returning {@link FormValidation#error(String)} does not
		 *      prevent the form from being saved. It just means that a message
		 *      will be displayed to the user.
		 */
		public FormValidation doCheckFilenameReports(@QueryParameter("filenameReports") final String filenameReports)
				throws IOException, ServletException {
			if(filenameReports.isEmpty())
				return FormValidation.error("Field is required");
			if(!FilenameUtils.getExtension(filenameReports).equals(""))
				return FormValidation.warning("A file extension is not necessary.");
			return FormValidation.ok();
		}
		
		/**
		 * Performs on-the-fly validation of the form field 'filenameSaveSession'.
		 * <p>
		 * If the user wants to save session whereas a session is already loaded, 
		 * the relative path to the saved session must be different from the relative path to the loaded session.
		 *
		 * @param filenameLoadSession
		 *      Parameter to compare with filenameSaveSession.
		 * @param filenameSaveSession
		 *      This parameter receives the value that the user has typed.
		 * @return
		 *      Indicates the outcome of the validation. This is sent to the browser.
		 *      <p>
		 *      Note that returning {@link FormValidation#error(String)} does not
		 *      prevent the form from being saved. It just means that a message
		 *      will be displayed to the user.
		 */
		public FormValidation doCheckFilenameSaveSession(@QueryParameter("filenameLoadSession") final String filenameLoadSession,
				@QueryParameter("filenameSaveSession") final String filenameSaveSession)
				throws IOException, ServletException {
			if(filenameSaveSession.equals(filenameLoadSession))
				return FormValidation.error("The saved session filename is the same of the loaded session filename.");
			if(!filenameLoadSession.isEmpty())
				return FormValidation.warning("A session is loaded, so it's not necessary to save session");
			if(!FilenameUtils.getExtension(filenameSaveSession).equals(""))
				return FormValidation.warning("A file extension is not necessary. A default file extension will be added (.session)");
			return FormValidation.ok();
		}
		
		/**
		 * List model to choose the alert report format
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillChosenFormatItems() {
			ListBoxModel items = new ListBoxModel();
			for(String format: formatList)
				items.add(format);
			return items;
		}
		
		/**
		 * List model to choose the tool used (normally, it should be the ZAProxy tool)
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillToolUsedItems() {
			ListBoxModel items = new ListBoxModel();
			for (ToolDescriptor<?> desc : ToolInstallation.all()) {
				for (ToolInstallation tool : desc.getInstallations()) {
					items.add(tool.getName());
				}
			}
			return items;
		}
		
		/**
		 * List model to choose the policy file to use by ZAproxy scan.
		 * @param zapDefaultDir A string that represents an absolute path to the directory that ZAP uses.
		 * @return a {@link ListBoxModel}. It can be empty if zapDefaultDir doesn't contain any policy file.
		 */
		public ListBoxModel doFillChosenPolicyItems(@QueryParameter String zapDefaultDir) {
			ListBoxModel items = new ListBoxModel();
			
			File zapDir = new File(zapDefaultDir, NAME_POLICIES_DIR_ZAP);
			
			if(zapDir.exists()) {				
				// create new filename filter (get only file with FILE_POLICY_EXTENSION extension)
				FilenameFilter policyFilter = new FilenameFilter() {

					@Override
					public boolean accept(File dir, String name) {
						if (name.lastIndexOf('.') > 0) {
							// get last index for '.' char
							int lastIndex = name.lastIndexOf('.');

							// get extension
							String str = name.substring(lastIndex);

							// match path name extension
							if (str.equals(FILE_POLICY_EXTENSION)) {
								return true;
							}
						}
						return false;
					}
				};
				// returns pathnames for files and directory
				File[] listFiles = zapDir.listFiles(policyFilter);
				
				// Add policy files to the list, without their extension
				for(int i = 0; i < listFiles.length; i++) {
					items.add(FilenameUtils.getBaseName(listFiles[i].getName()));
				}
			}
			
			return items;
		}
	}
}
