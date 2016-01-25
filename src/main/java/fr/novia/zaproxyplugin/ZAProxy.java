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

import fr.novia.zaproxyplugin.report.ZAPreport;
import fr.novia.zaproxyplugin.report.ZAPreportCollection;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.model.AbstractDescribableImpl;
import hudson.model.BuildListener;
import hudson.model.EnvironmentSpecific;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.JDK;
import hudson.model.Node;
import hudson.remoting.VirtualChannel;
import hudson.slaves.NodeSpecific;
import hudson.slaves.SlaveComputer;
import hudson.tools.ToolDescriptor;
import hudson.tools.ToolInstallation;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import java.io.BufferedReader;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import jenkins.model.Jenkins;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;
//import org.parosproxy.paros.CommandLine;

/**
 * Contains methods to start and execute ZAProxy.
 * Members variables are bind to the config.jelly placed to fr/novia/zaproxyplugin/ZAProxy
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAProxy extends AbstractDescribableImpl<ZAProxy> implements Serializable  {

	private static final long serialVersionUID = 3381268691497579059L;

	private static final String API_KEY = "ZAPROXY-PLUGIN";
	
	private static final int MILLISECONDS_IN_SECOND = 1000;
	public static final String FILE_POLICY_EXTENSION = ".policy";
	public static final String FILE_SESSION_EXTENSION = ".session";
	public static final String NAME_POLICIES_DIR_ZAP = "policies";
	
	public static final String CMD_LINE_DIR = "-dir";
	public static final String CMD_LINE_HOST = "-host";
	public static final String CMD_LINE_PORT = "-port";
	public static final String CMD_LINE_DAEMON = "-daemon";
	private static final String CMD_LINE_CONFIG = "-config";
	private static final String CMD_LINE_API_KEY = "api.key";
	
	// TODO Do import when zap-2.4.0.jar will contain the correct API version
//	public static final String CMD_LINE_DIR = CommandLine.DIR;
//	public static final String CMD_LINE_CONFIG = CommandLine.CONFIG;
//	public static final String CMD_LINE_HOST = CommandLine.HOST;
//	public static final String CMD_LINE_PORT = CommandLine.PORT;
//	public static final String CMD_LINE_DAEMON = CommandLine.DAEMON;
	
	private static final String ZAP_PROG_NAME_BAT = "zap.bat";
	private static final String ZAP_PROG_NAME_SH = "zap.sh";


	
	/** Host configured when ZAProxy is used as proxy */
	private String zapProxyHost;
	
	/** Port configured when ZAProxy is used as proxy */
	private int zapProxyPort;
	
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

	/** Filename to load ZAProxy session. Contains the absolute path to the session */
	private final String filenameLoadSession;
	
	/** URL to attack by ZAProxy */
	private final String targetURL;
	
	/** Exclude url from scan **/
	private final String excludedUrl;
	
	/** the scan mode (AUTHENTICATED/NOT_AUTHENTICATED) */
	private final String scanMode;
	
	/** Realize a url spider or not by ZAProxy */
	private final boolean spiderURL;

	/** Realize a url spider as user or not by ZAProxy */
	private final boolean spiderAsUser;
	
	/** Realize a url scan as user or not by ZAProxy */
	private final boolean scanURLAsUser;

	/** Authentication information for conducting spidering,ajax spidering or scan as a user*/
	/** user name for authentication*/
	private final String username;

	/** Password for the defined user */
	private final String password;
	
	/** username post data parameter*/
	private final String usernameParameter;
	
	/** password post data parameter*/
	private final String passwordParameter;
	
	/** extra post data needed to authenticate the user*/	
	private final String extraPostData;
	
	/** loggin url**/
	private final String loginUrl;

	/** logged in indication*/
	private final String loggedInIndicator;

	/** Id of the newly created context*/
	private String contextId;

	/** Id of the newly created user*/
	private String userId;

	/** Realize a url AjaxSpider or not by ZAProxy */
	private final boolean ajaxSpiderURL;
	
	/** Realize a url AjaxSpider as user or not by ZAProxy */
	private final boolean ajaxSpiderURLAsUser;
	
	/** Realize a url scan or not by ZAProxy */
	private final boolean scanURL;
	
	/** Save reports or not */
	private final boolean saveReports;

	/** List of chosen format for reports.
	 * ArrayList because it needs to be Serializable (whereas List is not Serializable)
	 */
	private final ArrayList<String> chosenFormats;
	
	/** Filename for ZAProxy reports. It can contain a relative path. */
	private  String filenameReports;
	
	/** Save session or not */
	private final boolean saveSession;
	
	/** Filename to save ZAProxy session. It can contain a relative path. */
	private final String filenameSaveSession;
	
	/** The default directory that ZAP uses */
	private final String zapDefaultDir;
	
	/** The file policy to use for the scan. It contains only the policy name (without extension) */
	private final String chosenPolicy;
	
	/** List of all ZAP command lines specified by the user 
	 * ArrayList because it needs to be Serializable (whereas List is not Serializable)
	 */
	private final ArrayList<ZAPcmdLine> cmdLinesZAP;
	
	/** The jdk to use to start ZAProxy */
	private final String jdk;


	/** List of all parameters used for the
	 * ZAP addon jiraIssueCreater
	 */

	/** create jiras or not */
	private final boolean createJiras;

	private  String jiraBaseURL;

	private  String jiraUserName;

	private String jiraPassword;

	/** The jira project key */
	private final String projectKey;

	/** The jira assignee */
	private final String assignee;

	/** select alert type high */
	private final boolean alertHigh;

	/** select alert type medium */
	private final boolean alertMedium;

	/** select alert type low */
	private final boolean alertLow;

	/** Filetr issues by resource type */
	private final boolean filterIssuesByResourceType;


	/**
     * @deprecated
     * Old constructor 
     */
	@Deprecated
	public ZAProxy(boolean autoInstall, String toolUsed, String zapHome, int timeoutInSec,
			String filenameLoadSession, String targetURL, boolean spiderURL, boolean scanURL,boolean scanURLAsUser,
			boolean saveReports, List<String> chosenFormats, String filenameReports,
			boolean saveSession, String filenameSaveSession,
			String zapDefaultDir, String chosenPolicy,
			List<ZAPcmdLine> cmdLinesZAP, String jdk, boolean createJiras, String jiraBaseURL, String jiraUserName, String jiraPassword,
				   String projectKey,  String assignee, boolean alertHigh, boolean alertMedium,
				   boolean alertLow, boolean filterIssuesByResourceType ) {
		
		this.autoInstall = autoInstall;
		this.toolUsed = toolUsed;
		this.zapHome = zapHome;
		this.timeoutInSec = timeoutInSec;
		this.filenameLoadSession = filenameLoadSession;
		this.targetURL = targetURL;
		this.spiderURL = spiderURL;
		this.scanURL = scanURL;
		this.scanURLAsUser=scanURLAsUser;
		this.saveReports = saveReports;
		this.chosenFormats = chosenFormats != null ? new ArrayList<String>(chosenFormats) : new ArrayList<String>();
		this.filenameReports = filenameReports;
		this.saveSession = saveSession;
		this.filenameSaveSession = filenameSaveSession;
		this.zapDefaultDir = zapDefaultDir;
		this.chosenPolicy = chosenPolicy;
		this.cmdLinesZAP = cmdLinesZAP != null ? new ArrayList<ZAPcmdLine>(cmdLinesZAP) : new ArrayList<ZAPcmdLine>();
		this.ajaxSpiderURL=false;
		this.ajaxSpiderURLAsUser=false;
		this.jdk = jdk;
		
		this.spiderAsUser=false;
		this.username="";
		this.password="";
		this.usernameParameter="";
		this.passwordParameter="";
		this.extraPostData="";
		this.loginUrl="";
		this.loggedInIndicator="";
		this.excludedUrl="";
		this.scanMode="";

		this.jiraBaseURL=jiraBaseURL;
		this.jiraUserName=jiraUserName;
		this.jiraPassword=jiraPassword;
		this.projectKey=projectKey;
		this.createJiras=createJiras;
		this.assignee=assignee;
		this.alertHigh=alertHigh;
		this.alertMedium=alertMedium;
		this.alertLow=alertLow;
		this.filterIssuesByResourceType=filterIssuesByResourceType;

		System.out.println(this.toString());
	}

	@DataBoundConstructor
	public ZAProxy(boolean autoInstall, String toolUsed, String zapHome, int timeoutInSec,
			String filenameLoadSession, String targetURL,String excludedUrl, String scanMode, boolean spiderURL, boolean spiderAsUser, boolean ajaxSpiderURL,boolean ajaxSpiderURLAsUser, 
			boolean scanURL, boolean scanURLAsUser,boolean saveReports, List<String> chosenFormats, String filenameReports,
			boolean saveSession, String filenameSaveSession, String zapDefaultDir, String chosenPolicy,
			List<ZAPcmdLine> cmdLinesZAP, String jdk, String username, String password, String usernameParameter, 
			String passwordParameter, String extraPostData,String loginUrl, String loggedInIndicator,boolean createJiras,
				   String jiraBaseURL, String jiraUserName, String jiraPassword, String projectKey,
				   String assignee, boolean alertHigh, boolean alertMedium, boolean alertLow, boolean filterIssuesByResourceType) {
		
		this.autoInstall = autoInstall;
		this.toolUsed = toolUsed;
		this.zapHome = zapHome;
		this.timeoutInSec = timeoutInSec;
		this.filenameLoadSession = filenameLoadSession;
		this.targetURL = targetURL;
		this.excludedUrl=excludedUrl;
		this.scanMode=scanMode;
		this.spiderURL = spiderURL;
		this.ajaxSpiderURL=ajaxSpiderURL;
		this.ajaxSpiderURLAsUser=ajaxSpiderURLAsUser;
		this.scanURL = scanURL;
		this.scanURLAsUser=scanURLAsUser;
		this.saveReports = saveReports;
		this.chosenFormats = chosenFormats != null ? new ArrayList<String>(chosenFormats) : new ArrayList<String>();
		this.filenameReports = filenameReports;
		this.saveSession = saveSession;
		this.filenameSaveSession = filenameSaveSession;
		this.zapDefaultDir = zapDefaultDir;
		this.chosenPolicy = chosenPolicy;
		this.cmdLinesZAP = cmdLinesZAP != null ? new ArrayList<ZAPcmdLine>(cmdLinesZAP) : new ArrayList<ZAPcmdLine>();
		
		this.spiderAsUser=spiderAsUser;
		this.username=username;
		this.password=password;
		this.usernameParameter=usernameParameter;
		this.passwordParameter=passwordParameter;
		this.extraPostData=extraPostData;
		this.loginUrl=loginUrl;
		this.loggedInIndicator=loggedInIndicator;

		this.jdk = jdk;

		this.projectKey=projectKey;
		this.createJiras=createJiras;
		this.jiraUserName=jiraUserName;
		this.jiraPassword=jiraPassword;
		this.assignee=assignee;
		this.alertHigh=alertHigh;
		this.alertMedium=alertMedium;
		this.alertLow=alertLow;
//		this.selectProjectKeys = selectProjectKeys != null ? new ArrayList<String>(selectProjectKeys) : new ArrayList<String>();
		this.jiraBaseURL=jiraBaseURL;
		this.filterIssuesByResourceType=filterIssuesByResourceType;
		System.out.println(this.toString());
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
		s += "excludedUrl ["+excludedUrl+"]\n";
		s += "scanMode ["+scanMode+"]\n";		
		s += "spiderURL ["+spiderURL+"]\n";
		s += "spider as user ["+spiderAsUser+"]\n";
		s += "usernameParameter ["+usernameParameter+"]\n";
		s += "username ["+username+"]\n";
		s += "passwordParameter ["+passwordParameter+"]\n";
		s += "extraPostData ["+extraPostData+"]\n";
		s += "loginUrl ["+loginUrl+"]\n";
		s += "loggedInIndicator ["+loggedInIndicator+"]\n";
		s += "ajaxSpiderURL ["+ajaxSpiderURL+"]\n";
		s += "ajaxSpiderURLAsUser ["+ajaxSpiderURLAsUser+"]\n";
		s += "scanURL ["+scanURL+"]\n";
		s += "scanURLAsUser ["+scanURLAsUser+"]\n";
		s += "saveReports ["+saveReports+"]\n";
		s += "chosenFormats ["+chosenFormats+"]\n";
		s += "filenameReports ["+filenameReports+"]\n";
		s += "saveSession ["+saveSession+"]\n";
		s += "filenameSaveSession ["+filenameSaveSession+"]\n";
		s += "zapDefaultDir ["+zapDefaultDir+"]\n";
		s += "chosenPolicy ["+chosenPolicy+"]\n";
		
		s += "zapProxyHost ["+zapProxyHost+"]\n";
		s += "zapProxyPort ["+zapProxyPort+"]\n";
		
		s+= "jdk ["+jdk+"]";

		s+= "createJiras ["+createJiras+"]\n";
		s+= "jiraBaseURL ["+jiraBaseURL+"]\n";
		s+= "jiraUserName ["+jiraUserName+"]\n";
		s+= "jiraPassword ["+jiraPassword+"]\n";
		s+= "projectKey ["+projectKey+"]\n";
		s+= "assignee ["+assignee+"]\n";
		s+= "alertHigh ["+alertHigh+"]\n";
		s+= "alertMedium ["+alertMedium+"]\n";
		s+= "alertLow ["+alertLow+"]\n";
		s+="filterIssuesByResourceType["+filterIssuesByResourceType+"]\n";
		
		return s;
	}
	
	/**
	 * @param filenameReports the filenameReports to set
	 */
	public void setFilenameReports(String filenameReports) {
		this.filenameReports = filenameReports;
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
	public String getExcludedUrl() {
		return excludedUrl;
	}
	
	public String getScanMode(){
		return scanMode;
	}
	
	public boolean getSpiderURL() {
		return spiderURL;
	}

	public boolean getAjaxSpiderURL() {
		return ajaxSpiderURL;
	}
	
	public boolean getAjaxSpiderURLAsUser() {
		return ajaxSpiderURLAsUser;
	}

	public boolean getScanURL() {
		return scanURL;
	}

	public boolean getSaveReports() {
		return saveReports;
	}

	public List<String> getChosenFormats() {
		return chosenFormats;
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
	
	public List<ZAPcmdLine> getCmdLinesZAP() {
		return cmdLinesZAP;
	}

	public boolean getSpiderAsUser() {
		return spiderAsUser;
	}

	/**
	 * @return the scanURLAsUser
	 */
	public boolean getScanURLAsUser() {
		return scanURLAsUser;
	}

	public String  getUsernameParameter() {
		return usernameParameter;
	}

	public String  getpasswordParameter() {
		return passwordParameter;
	}
	
	public String  getusername() {
		return username;
	}

	public String getpassword() {
		return password;
	}

	public String getExtraPostData() {
		return extraPostData;
	}

	public String getLoginUrl() {
		return loginUrl;
	}

	public String getLoggedInIndicator() {
		return loggedInIndicator;
	}

	public boolean getcreateJiras(){
		return  createJiras;
	}

	public String getProjectKey(){
		return projectKey;
	}

	public String getassignee(){
		return projectKey;
	}

	public boolean getalertHigh(){
		return alertHigh;
	}

	public boolean getalertMedium(){
		return alertMedium;
	}

	public boolean getalertLow(){
		return alertLow;
	}

	public boolean getfilterIssuesByResourceType(){ return filterIssuesByResourceType; }

//	public List<String> getselectProjectKeys(){return  selectProjectKeys;}

	/*gets and sets the values from the credentials and base urls
	* method call is from Zaproxybuilder*/

	public void setJiraBaseURL(String jiraBaseURL){ this.jiraBaseURL=jiraBaseURL; }

	public void setJiraUserName(String jiraUserName){this.jiraUserName=jiraUserName;}

	public void setJiraPassword(String jiraPassword){this.jiraPassword=jiraPassword;}

	/**
	 * Gets the JDK that this Sonar builder is configured with, or null.
	 */
	public JDK getJDK() {
		return Jenkins.getInstance().getJDK(jdk);
	}

	public String getJdk() {
		return jdk;
	}
	
	/**
	 * Test if the test type names match (for marking the radio button).
	 * 
	 * @param testTypeName
	 *            The String representation of the test type.
	 * @return Whether or not the test type string matches.
	 */
	public String isScanMode(String testTypeName) {
		return this.scanMode.equalsIgnoreCase(testTypeName) ? "true" : "";
	}

	/**
	 * Get the ZAP_HOME setup by Custom Tools Plugin or already present on the build's machine. 
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @return the installed tool location, without zap.bat or zap.sh at the end
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @see <a href="https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk">
	 * 	https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk</a>
	 */
	private String retrieveZapHomeWithToolInstall(AbstractBuild<?, ?> build, BuildListener listener) 
			throws IOException, InterruptedException {	
		
		EnvVars env = null;
		Node node = null;
		String installPath = null;
			
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
		if( "".equals(node.getNodeName())) { // Master
			if( File.pathSeparatorChar == ':' ) { // UNIX
				zapProgramName = ZAP_PROG_NAME_SH;
			} else { // Windows (pathSeparatorChar == ';')
				zapProgramName = ZAP_PROG_NAME_BAT;
			}
		} 
		else { // Slave
			if( "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription()) ) {
				zapProgramName = ZAP_PROG_NAME_SH;
			} else {
				zapProgramName = ZAP_PROG_NAME_BAT;
			}
		}
		return zapProgramName;
	}
	
	/**
	 * Return the ZAProxy program name with separator prefix (\zap.bat or /zap.sh) depending of the build node and the OS.
	 * 
	 * @param build
	 * @return the ZAProxy program name with separator prefix (\zap.bat or /zap.sh)
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private String getZAPProgramNameWithSeparator(AbstractBuild<?, ?> build) throws IOException, InterruptedException {
		Node node = build.getBuiltOn();
		String zapProgramName = "";
		
		// Append zap program following Master/Slave and Windows/Unix
		if( "".equals(node.getNodeName())) { // Master
			if( File.pathSeparatorChar == ':' ) { // UNIX
				zapProgramName = "/" + ZAP_PROG_NAME_SH;
			} else { // Windows (pathSeparatorChar == ';')
				zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
			}
		} 
		else { // Slave
			if( "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription()) ) {
				zapProgramName = "/" + ZAP_PROG_NAME_SH;
			} else {
				zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
			}
		}
		return zapProgramName;
	}
	
	/**
	 * Verify parameters of the build setup are correct (null, empty, negative ...)
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @throws Exception throw an exception if a parameter is invalid.
	 */
	private void checkParams(AbstractBuild<?, ?> build, BuildListener listener) 
			throws IllegalArgumentException, IOException, InterruptedException {
		zapProgram = retrieveZapHomeWithToolInstall(build, listener);
		
		if(zapProgram == null || zapProgram.isEmpty()) {
			throw new IllegalArgumentException("zapProgram is missing");
		} else
			listener.getLogger().println("zapProgram = " + zapProgram);
		
		if(targetURL == null || targetURL.isEmpty()) {
			throw new IllegalArgumentException("targetURL is missing");
		} else
			listener.getLogger().println("targetURL = " + targetURL);

		if(zapProxyHost == null || zapProxyHost.isEmpty()) {
			throw new IllegalArgumentException("zapProxy Host is missing");
		} else
			listener.getLogger().println("zapProxyHost = " + zapProxyHost);

		if(zapProxyPort < 0) {
			throw new IllegalArgumentException("zapProxy Port is less than 0");
		} else
			listener.getLogger().println("zapProxyPort = " + zapProxyPort);

		if(jiraBaseURL.equals(null)) {
			throw new IllegalArgumentException("Jira Base URL not Found");
		} else
			listener.getLogger().println("jiraBaseURL = " + jiraBaseURL);

		if(jiraUserName.equals(null)) {
			throw new IllegalArgumentException("Jira User name not Found");
		} else
			listener.getLogger().println("jiraUserName = " + jiraUserName);

		if(jiraPassword.equals(null)) {
			throw new IllegalArgumentException("Jira password not Found");
		} else {
			String pass = "";
			for (int i = 0; i < jiraPassword.length(); i++) {
				pass += "*";
			}
			listener.getLogger().println("jiraUserName = " + pass);
		}
		
	}
		
	/**
	 * Start ZAProxy using command line. It uses host and port configured in Jenkins admin mode and
	 * ZAProxy program is launched in daemon mode (i.e without UI).
	 * ZAProxy is started on the build's machine (so master machine ou slave machine) thanks to 
	 * {@link FilePath} object and {@link Launcher} object.
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param launcher the object to launch a process locally or remotely
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void startZAP(AbstractBuild<?, ?> build, BuildListener listener, Launcher launcher) 
			throws IllegalArgumentException, IOException, InterruptedException {
		checkParams(build, listener);
		
		FilePath ws = build.getWorkspace();
		if (ws == null) {
			Node node = build.getBuiltOn();
			if (node == null) {
				throw new NullPointerException("no such build node: " + build.getBuiltOnStr());
			}
			throw new NullPointerException("no workspace from node " + node + " which is computer " + node.toComputer() + " and has channel " + node.getChannel());
		}
		
		// Contains the absolute path to ZAP program
		FilePath zapPathWithProgName = new FilePath(ws.getChannel(), zapProgram + getZAPProgramNameWithSeparator(build));
		listener.getLogger().println("Start ZAProxy [" + zapPathWithProgName.getRemote() + "]");
		
		// Command to start ZAProxy with parameters
		List<String> cmd = new ArrayList<String>();
		cmd.add(zapPathWithProgName.getRemote());
		cmd.add(CMD_LINE_DAEMON);
		cmd.add(CMD_LINE_HOST);
		cmd.add(zapProxyHost);
		cmd.add(CMD_LINE_PORT);
		cmd.add(String.valueOf(zapProxyPort));
		cmd.add(CMD_LINE_CONFIG);
		cmd.add(CMD_LINE_API_KEY + "=" + API_KEY);
		
		// Set the default directory used by ZAP if it's defined and if a scan is provided
		if(scanURL && zapDefaultDir != null && !zapDefaultDir.isEmpty()) {
			cmd.add(CMD_LINE_DIR);
			cmd.add(zapDefaultDir);
		}
		
		// Adds command line arguments if it's provided
		if(!cmdLinesZAP.isEmpty()) {
			addZapCmdLine(cmd);
		}
			
		EnvVars envVars = build.getEnvironment(listener);
		// on Windows environment variables are converted to all upper case,
		// but no such conversions are done on Unix, so to make this cross-platform,
		// convert variables to all upper cases.
		for(Map.Entry<String,String> e : build.getBuildVariables().entrySet())
			envVars.put(e.getKey(),e.getValue());
		
		FilePath workDir = new FilePath(ws.getChannel(), zapProgram);
		
		// JDK choice
		computeJdkToUse(build, listener, envVars);
		
		// Launch ZAP process on remote machine (on master if no remote machine)
		launcher.launch().cmds(cmd).envs(envVars).stdout(listener).pwd(workDir).start();
		
		// Call waitForSuccessfulConnectionToZap(int, BuildListener) remotely
		build.getWorkspace().act(new WaitZAProxyInitCallable(this, listener));
	}
	
	/**
	 * Set the JDK to use to start ZAP.
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param env list of environment variables. Used to set the path to the JDK
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private void computeJdkToUse(AbstractBuild<?, ?> build,
			BuildListener listener, EnvVars env) throws IOException, InterruptedException {
		JDK jdkToUse = getJdkToUse(build.getProject());
		if (jdkToUse != null) {
			Computer computer = Computer.currentComputer();
			// just in case we are not in a build
			if (computer != null) {
				jdkToUse = jdkToUse.forNode(computer.getNode(), listener);
			}
			jdkToUse.buildEnvVars(env);
		}
	}

	/**
	 * @return JDK to be used with this project.
	 */
	private JDK getJdkToUse(AbstractProject<?, ?> project) {
		JDK jdkToUse = getJDK();
		if (jdkToUse == null) {
			jdkToUse = project.getJDK();
		}
		return jdkToUse;
	}
	
	/**
	 * Add list of command line in the list in param
	 * @param l the list to attach ZAP command line
	 */
	private void addZapCmdLine(List<String> l) {
		for(ZAPcmdLine zapCmd : cmdLinesZAP) {
			if(zapCmd.getCmdLineOption() != null && !zapCmd.getCmdLineOption().isEmpty()) {
				l.add(zapCmd.getCmdLineOption());
			}
			if(zapCmd.getCmdLineValue() != null && !zapCmd.getCmdLineValue().isEmpty()) {
				l.add(zapCmd.getCmdLineValue());
			}
		}
	}
	
	/**
	 * Wait for ZAProxy initialization, so it's ready to use at the end of this method
	 * (otherwise, catch exception). This method is launched on the remote machine (if there is one)
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
				listener.error(ExceptionUtils.getStackTrace(ignore));
				throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
				
			} catch (IOException ignore) {
				// and keep trying but wait some time first...
				try {
					Thread.sleep(pollingIntervalInMs);
				} catch (InterruptedException e) {
					listener.error(ExceptionUtils.getStackTrace(ignore));
					throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
				}

				long ellapsedTime = System.currentTimeMillis() - startTime;
				if (ellapsedTime >= timeoutInMs) {
					listener.error(ExceptionUtils.getStackTrace(ignore));
					throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
				}
				connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
			} finally {
				if(socket != null) {
					try {
						socket.close();
					} catch (IOException e) {
						listener.error(ExceptionUtils.getStackTrace(e));
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
	 * @throws IOException 
	 * @throws Exception
	 */
	private String getAllAlerts(final String format, BuildListener listener) throws IOException {
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
	 * Generates security report for one format. Reports are saved into build's workspace.
	 * 
	 * @param reportFormat the format of the report
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param workspace a {@link FilePath} representing the build's workspace
	 * @param clientApi the ZAP client API to call method
	 * @throws ClientApiException 
	 * @throws IOException
	 */
	private void saveReport(ZAPreport reportFormat, BuildListener listener, FilePath workspace, 
			ClientApi clientApi) throws IOException, ClientApiException {
		final String fullFileName = filenameReports + "." + reportFormat.getFormat();
		File reportsFile = new File(workspace.getRemote(), fullFileName);
		FileUtils.writeByteArrayToFile(reportsFile, reportFormat.generateReport(clientApi, API_KEY));
		listener.getLogger().println("File [" + reportsFile.getAbsolutePath() + "] saved");
	}

	/**
	 * Execute ZAProxy method following build's setup and stop ZAP at the end.
	 * 
	 * @param workspace a {@link FilePath} representing the build's workspace
	 * @param listener the listener to display log during the job execution in jenkins
	 * @return true is no exception is caught, false otherwise.
	 */
	public boolean executeZAP(FilePath workspace, BuildListener listener) {
		ClientApi zapClientAPI = new ClientApi(zapProxyHost, zapProxyPort);
		boolean buildSuccess = true;	
		
		
		// Try/catch here because I need to stopZAP in finally block and for that,
		// I need the zapClientAPI created in this method
		try {
			/* ======================================================= 
			 * |                  LOAD SESSION                        |
			 * ======================================================= 
			 */
			if(filenameLoadSession != null && filenameLoadSession.length() != 0) {
				File sessionFile = new File(filenameLoadSession);
				listener.getLogger().println("Load session at ["+ sessionFile.getAbsolutePath() +"]");
				zapClientAPI.core.loadSession(API_KEY, sessionFile.getAbsolutePath());
			} else {
				listener.getLogger().println("Skip loadSession");
			}
			
			/* ======================================================= 
			 * |                  SE UP CONTEXT                       |
			 * ======================================================= 
			 */
			
			//setup context
			this.contextId=setUpContext(listener,targetURL,excludedUrl,zapClientAPI);
			
			
			
			if(scanMode.equals("NOT_AUTHENTICATED")) {

			 
				listener.getLogger().println("SCANMOD : NOT_AUTHENTICATED");
			
			//Non authenticated mod : spider url, ajax spider url, scan url
			/* ======================================================= 
			 * |                  SPIDER URL                          |
			 * ======================================================= 
			 */
			if (spiderURL) {
				listener.getLogger().println("Spider the site [" + targetURL + "]");
				spiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip spidering the site [" + targetURL + "]");
			}

			/* ======================================================= 
			 * |                AJAX SPIDER URL                       |
			 * ======================================================= 
			 */
			if (ajaxSpiderURL) {
				listener.getLogger().println("Ajax Spider the site [" + targetURL + "]");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "]");
			}
			
			/* ======================================================= 
			 * |                  SCAN URL                            |
			 * ======================================================= 
			 */
			if (scanURL) {				
				listener.getLogger().println("Scan the site [" + targetURL + "]");
				scanURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip scanning the site [" + targetURL + "]");
			}
			 
			} 
			
			else if(scanMode.equals("AUTHENTICATED"))   {

			listener.getLogger().println("SCANMOD : AUTHENTICATED");
			
			//Authenticated mod : spider url as user, ajax spider url as user, scan url as user

			/* ======================================================= 
			 * |                  SPIDER AS USER                      |
			 * ======================================================= 
			 */
			if (spiderAsUser) {
				listener.getLogger().println("Setting up Authentication");
				setUpAuthentication(targetURL,listener,zapClientAPI, username,password,usernameParameter,passwordParameter,extraPostData,loginUrl,loggedInIndicator);

				listener.getLogger().println("Spider the site [" + targetURL + "] as user ["+username+"]");				
				spiderURLAsUser(targetURL, listener, zapClientAPI, contextId, userId);
			} else {
				listener.getLogger().println("Skip spidering the site [" + targetURL + "] as user ["+username+"]");
			}
			
			/* ======================================================= 
			 * |                AJAX SPIDER URL AS USER               |
			 * ======================================================= 
			 */
			if (ajaxSpiderURLAsUser) {
				listener.getLogger().println("Ajax Spider the site [" + targetURL + "] as user ["+username+"]");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "] as user ["+username+"]");
			}

			/* ======================================================= 
			 * |                  SCAN URL AS USER                    |
			 * ======================================================= 
			 */
			if (scanURLAsUser) {				
				listener.getLogger().println("Scan the site [" + targetURL + "] as user ["+username+"]");
				scanURLAsUser(targetURL, listener, zapClientAPI,contextId, userId);
			} else {
				listener.getLogger().println("Skip scanning the site [" + targetURL + "] as user ["+username+"]");
			}
			
			 
			}
			
			
			/* ======================================================= 
			 * |                  SAVE REPORTS                        |
			 * ======================================================= 
			 */
			if (saveReports) {			
				// Generates reports for all formats selected
				for(String format : chosenFormats) {
					ZAPreport report = ZAPreportCollection.getInstance().getMapFormatReport().get(format);
					saveReport(report, listener, workspace, zapClientAPI);
				}
			}


			  /* =======================================================
			 * |                  CREATE JIRA ISSUES                       |
			 * =======================================================
			 */
			if (createJiras) {
				// Generates reports for all formats selected

				listener.getLogger().println("******************    Strated creating jiras    ************************");
				Map<String, String> map = null;
				map = new HashMap<String, String>();

				if (API_KEY != null) {
					map.put("apikey", API_KEY);
				}
				map.put("jiraBaseURL",jiraBaseURL);
				map.put("jiraUserName",jiraUserName);
				map.put("jiraPassword",jiraPassword);
				map.put("projectKey",projectKey);
				map.put("jiraUserName",jiraUserName);
				map.put("assignee",assignee);
				map.put("high",returnCheckedStatus(alertHigh));
				map.put("medium",returnCheckedStatus(alertMedium));
				map.put("low",returnCheckedStatus(alertLow));
				map.put("filterIssuesByResourceType",returnCheckedStatus(filterIssuesByResourceType));

				listener.getLogger().println("******************    initialized variables     *************************");

				listener.getLogger().println("            Api key  : " + API_KEY);
				listener.getLogger().println("            Base URL  : " + jiraBaseURL);
				listener.getLogger().println("            UserName  : " + jiraUserName);
				listener.getLogger().println("            Project key  : " + projectKey);
				listener.getLogger().println("            Assignee  : " + assignee);
				listener.getLogger().println("            Export High alerts  : " + alertHigh);
				listener.getLogger().println("            Export Medium alerts  : "+alertMedium);
				listener.getLogger().println("            Export Low alerts  : "+alertLow);
				listener.getLogger().println("            Filter by resource Type  : "+filterIssuesByResourceType);

				try{

					zapClientAPI.callApi("jiraIssueCreater", "action", "createJiraIssues", map);

				}catch(ClientApiException e){

					listener.getLogger().println(e.getMessage());
				}

			}else{
				listener.getLogger().println("Skiped creating jiras");
			}


			
			/* ======================================================= 
			 * |                  SAVE SESSION                        |
			 * ======================================================= 
			 */
			if(saveSession) {
				if(filenameSaveSession != null && !filenameSaveSession.isEmpty()) {
					File sessionFile = new File(workspace.getRemote(), filenameSaveSession);
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
			
			listener.getLogger().println("Total alerts = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			listener.getLogger().println("Total messages = " + zapClientAPI.core.numberOfMessages("").toString(2));
			
		} catch (Exception e) {
			listener.error(ExceptionUtils.getStackTrace(e));
			buildSuccess = false;
		} finally {
			try {
				stopZAP(zapClientAPI, listener);
			} catch (ClientApiException e) {
				listener.error(ExceptionUtils.getStackTrace(e));
				buildSuccess = false;
			}
		}
		return buildSuccess;
	}

	/**method used to return the checked state
	 * inside CREATE JIRA ISSUES
	 * **/
	private String returnCheckedStatus(boolean checkedStatus){
		if(checkedStatus){
			return "1";
		}else{
			return "0";
		}
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
	 * Converts the ZAP API status response to an String
	 *
	 * @param response the ZAP API response code
	 * @return the String status of the ApiResponse
	 */
	@SuppressWarnings("unchecked")
	private String statusToString(final ApiResponse response) {
		return ((ApiResponseElement)response).getValue();
	}

	/**
	 *get user id
	 * @param response the ZAP API response code
	 * @return the user ID of the  user
	 */
	@SuppressWarnings("unchecked")
	private String extractUserId(ApiResponse response) {
		return ((ApiResponseElement) response).getValue();
	}

	/**
	 *get context id
	 * @param response the ZAP API response code
	 * @return the context ID of the context
	 */
	@SuppressWarnings("unchecked")
	private String extractContextId(ApiResponse response) {
		return ((ApiResponseElement) response).getValue();
	}

	/**
	 * set up a context and add/exclude url to/from it
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param URL the URL to be added to context
	 * @param excludedUrl the URL to exclude from context
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @return the context ID of the context
	 * @throws ClientApiException
	 */
	private String setUpContext(BuildListener listener, String url, String excludedUrl,ClientApi zapClientAPI) 
				throws ClientApiException {
		
		url=url.trim();
		//excludedUrl=excludedUrl.trim();
		
		String contextName="context1";//name of the Context to be created
		String contextURL="\\Q"+url+"\\E.*";//url to be added to the context (the same url given by the user to be scanned)
		
		
		String contextIdTemp;

		//Create new context
		//method signature : newContext(String apikey,String contextname) throws ClientApiException
		contextIdTemp=extractContextId(zapClientAPI.context.newContext(API_KEY,contextName));

		//add url to the context
		//method signature : includeInContext(String apikey, String contextname, String regex) 
		//					 throws ClientApiException
		zapClientAPI.context.includeInContext(API_KEY,contextName,contextURL);
		listener.getLogger().println("URL "+url+" added to Context ["+contextIdTemp+"]");
		
		//excluded urls from context
		if (!excludedUrl.equals("")) {
			
			try {

				String[] urls = excludedUrl.split("\n");
				String contextExcludedUrl="";//url to exclude from context like the log out url
			

				for (int i = 0; i < urls.length; i++) {
					urls[i] = urls[i].trim();
					if (!urls[i].isEmpty()) {
						contextExcludedUrl="\\Q"+urls[i]+"\\E";
						zapClientAPI.context.excludeFromContext(API_KEY, contextName, contextExcludedUrl);
						listener.getLogger().println("URL exluded from context : "+urls[i]);
					}

				}

			} catch (ClientApiException e) {
				e.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e));
			}
			 
		}

		
		
		return contextIdTemp;
	}

	/**
	 * set up authentication method for the created context
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param loggedInIdicator indication for know its logged in
	 * @param usernameParameter parameter define in passing username
	 * @param passwordParameter parameter that define in passing password for the user
	 * @param extraPostData other post data than credentials
	 * @param contextId id of the creted context
	 * @param loginUrl login page url
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	private void setUpAuthenticationMethod(BuildListener listener, ClientApi zapClientAPI, 
				String loggedInIndicator, String usernameParameter, String passwordParameter,String extraPostData,
				String contextId, String loginUrl) 
				throws ClientApiException, UnsupportedEncodingException{

		String loginRequestData = usernameParameter+"={%username%}&"+passwordParameter+"={%password%}&"+extraPostData;

		// set authentication method 		
		// Prepare the configuration in a format similar to how URL parameters are formed. This
		// means that any value we add for the configuration values has to be URL encoded.
		StringBuilder formBasedConfig = new StringBuilder();
		formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
		formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));

		zapClientAPI.authentication.setAuthenticationMethod(API_KEY, contextId, "formBasedAuthentication",
				formBasedConfig.toString());
		
		//end set auth method
		listener.getLogger().println("Form Based Authentication added to context");

		//add logged in idicator
		zapClientAPI.authentication.setLoggedInIndicator(API_KEY, contextId, loggedInIndicator);
		listener.getLogger().println("Logged in indicator "+loggedInIndicator+" added to context ");

	}

	/**
	 * set up user for the context and enable user
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param username user name to be used in authentication
	 * @param password password for the authentication user
	 * @param contextId id of the created context
	 * @return userId id of the newly setup user
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException 
	 */
	private String setUpUser(BuildListener listener, ClientApi zapClientAPI, String username,
						String password, String contextId) 
						throws ClientApiException, UnsupportedEncodingException {

		String userIdTemp;
		// add new user and authentication details
		// Make sure we have at least one user
		// extract user id 
		userIdTemp = extractUserId(zapClientAPI.users.newUser(API_KEY, contextId, username));

		// Prepare the configuration in a format similar to how URL parameters are formed. This
		// means that any value we add for the configuration values has to be URL encoded.
		StringBuilder userAuthConfig = new StringBuilder();
		userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8"));
		userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8"));
		String authCon=userAuthConfig.toString();
		
		zapClientAPI.users.setAuthenticationCredentials(API_KEY, contextId, userIdTemp, authCon);

		listener.getLogger().println("New user added. username :" +username);
		
		zapClientAPI.users.setUserEnabled(API_KEY, contextId,userIdTemp,"true");
		listener.getLogger().println("User : "+username+" is now Enabled");
		
		//to make spidering and ajax spidering in authentication mod
		setUpForcedUser(listener, zapClientAPI, contextId,  userIdTemp) ;

		return userIdTemp;
	}
	
	/**
	 * set up forced user for the context and enable user, this help to make spidering and ajax spidering as authenticated user
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param contextId id of the created context
	 * @return userId id of the newly setup user
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException 
	 */
	private void setUpForcedUser(BuildListener listener, ClientApi zapClientAPI, String contextid, String userid) 
						throws ClientApiException, UnsupportedEncodingException {
		
		zapClientAPI.forcedUser.setForcedUser(API_KEY, contextid,userid);
		zapClientAPI.forcedUser.setForcedUserModeEnabled(API_KEY, true);
		

	}
	
	
	/**
	 * Set up all authentication details
	 * @author thilina27
	 * @param username user name to be used in authentication
	 * @param password password for the authentication user
	 * @param usernameParameter parameter define in passing username
	 * @param passwordParameter parameter that define in passing password for the user
	 * @param extraPostData other post data than credentials
	 * @param loginUrl login page url
	 * @param loggedInIdicator indication for know its logged in
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 * @throws UnsupportedEncodingException
	 */
	private void setUpAuthentication(final String url, BuildListener listener, ClientApi zapClientAPI, 
				String username, String password, String usernameParameter, 
				String passwordParameter, String extraPostData, String loginUrl, String loggedInIndicator)
				throws ClientApiException, UnsupportedEncodingException {

		//setup context
		//this.contextId=setUpContext(listener,url,zapClientAPI);
				
		//set up authentication method
		setUpAuthenticationMethod(listener,zapClientAPI,loggedInIndicator,usernameParameter,
									passwordParameter,extraPostData,contextId,loginUrl);

		//set up user
		this.userId=setUpUser(listener,zapClientAPI,username,password,contextId);
	}
	
	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 *
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void spiderURL(final String url, BuildListener listener, ClientApi zapClientAPI) 
			throws ClientApiException, InterruptedException {
		// Method signature : scan(String key, String url, String maxChildren, String recurse)
		zapClientAPI.spider.scan(API_KEY, url, "", "");

		// Wait for complete spidering (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.spider.status("")) < 100) {
			listener.getLogger().println("Status spider = " + statusToInt(zapClientAPI.spider.status("")) + "%");
			listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			Thread.sleep(1000);
		}
	}

	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 * @author thilina27
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param contextId the id number of the contexte created for this scan
	 * @param userId the id number of the user created for this scan
	 * @throws ClientApiException
	 * @throws InterruptedException
	 */
	 
	private void spiderURLAsUser(final String url, BuildListener listener, ClientApi zapClientAPI, 
				String contextId, String userId)
				throws ClientApiException, InterruptedException {
		
		
		// Start spider as user
		zapClientAPI.spider.scanAsUser(API_KEY, url, contextId, userId, "0", "");
		
		// Wait for complete spidering (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.spider.status("")) < 100) {
			listener.getLogger().println("Status spider = " + statusToInt(zapClientAPI.spider.status("")) + "%");
			listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			Thread.sleep(1000);
		}
	}

	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 * @author thilina27
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void ajaxSpiderURL(final String url, BuildListener listener, ClientApi zapClientAPI) 
			throws ClientApiException, InterruptedException{


		//Method signature : scan(String apikey,String url,String inscope)
		zapClientAPI.ajaxSpider.scan(API_KEY, url, "false");
 		
 		// Wait for complete spidering (equal to status complete)
		// Method signature : status(String scanId)
		while ("running".equalsIgnoreCase(statusToString(zapClientAPI.ajaxSpider.status()))) { 
		    listener.getLogger().println("Status spider = " + statusToString(zapClientAPI.ajaxSpider.status()));
			listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			Thread.sleep(2500);
		} 
	}
	
	/**
	 * Scan all pages found at url and raised actives alerts
	 *
	 * @param url the url to scan
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void scanURL(final String url, BuildListener listener, ClientApi zapClientAPI) 
			throws ClientApiException, InterruptedException {
		if(chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default");		
		} else {
			listener.getLogger().println("Scan url [" + url + "] with the following policy ["
							+ chosenPolicy + "]");
		}
		
		// Method signature : scan(String apikey, String url, String recurse, String inscopeonly, String scanpolicyname, String method, String postdata)
		// Use a default policy if chosenPolicy is null or empty
		zapClientAPI.ascan.scan(API_KEY, url, "true", "false", chosenPolicy, null, null);

		// Wait for complete scanning (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.ascan.status("")) < 100) {
			listener.getLogger().println("Status scan = " + statusToInt(zapClientAPI.ascan.status("")) + "%");
			listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			listener.getLogger().println("Messages number = " + zapClientAPI.core.numberOfMessages("").toString(2));
			Thread.sleep(5000);
		}
	}
	
	/**
	 * Scan all pages found at url and raised actives alerts
	 *
	 * @author abdellah.azougarh
	 * @param url the url to scan
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param contextId the id number of the contexte created for this scan
	 * @param userId the id number of the user created for this scan
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void scanURLAsUser(final String url, BuildListener listener, ClientApi zapClientAPI, String contextId, String userId) 
			throws ClientApiException, InterruptedException {
		if(chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default");		
		} else {
			listener.getLogger().println("Scan url [" + url + "] with the following policy ["
							+ chosenPolicy + "]");
		}
		
		// Method signature : scan(String apikey, String url, String recurse, String inscopeonly, String scanpolicyname, String method, String postdata)
		// Use a default policy if chosenPolicy is null or empty
		zapClientAPI.ascan.scanAsUser(API_KEY, url, contextId, userId,"true", chosenPolicy, null, null);//arg2, arg3, arg4, arg5, arg6, arg7)scan(API_KEY, url, "true", "false", chosenPolicy, null, null);

		// Wait for complete scanning (equal to 100)
		// Method signature : status(String scanId)
		while (statusToInt(zapClientAPI.ascan.status("")) < 100) {
			listener.getLogger().println("Status scan = " + statusToInt(zapClientAPI.ascan.status("")) + "%");
			listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
			listener.getLogger().println("Messages number = " + zapClientAPI.core.numberOfMessages("").toString(2));
			Thread.sleep(5000);
		}
	}
	
	/**
	 * Stop ZAproxy if it has been previously started.
	 * 
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws ClientApiException 
	 */
	private void stopZAP(ClientApi zapClientAPI, BuildListener listener) throws ClientApiException {
		if (zapClientAPI != null) {
			listener.getLogger().println("Shutdown ZAProxy");
			//throw new ClientApiException("Exception lancee dans stopZAP");
			zapClientAPI.core.shutdown(API_KEY);
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
	public static class ZAProxyDescriptorImpl extends Descriptor<ZAProxy> implements Serializable {
		
		private static final long serialVersionUID = 4028279269334325901L;
		
		/**
		 * To persist global configuration information,
		 * simply store it in a field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		
		/** Map where key is the report format represented by a String
		 *  and value is a ZAPreport object allowing to generate a report with the corresponding format.
		 */
		private Map<String, ZAPreport> mapFormatReport;
		
		/** Represents the build's workspace */
		private FilePath workspace;
		
		/**
		 * In order to load the persisted global configuration, you have to
		 * call load() in the constructor.
		 */
		public ZAProxyDescriptorImpl() {
			mapFormatReport = ZAPreportCollection.getInstance().getMapFormatReport();
			load();
		}
		
		@Override
		public String getDisplayName() { 
			return null; 
		}

		public Map<String, ZAPreport> getMapFormatReport() {
			return mapFormatReport;
		}
		
		public List<String> getAllFormats() {
			return new ArrayList<String>(mapFormatReport.keySet());
		}
		
		public void setWorkspace(FilePath ws) {
			this.workspace = ws;
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
		public FormValidation doCheckFilenameReports(@QueryParameter("filenameReports") final String filenameReports) {
			if(filenameReports.isEmpty())
				return FormValidation.error("Field is required");
			if(!FilenameUtils.getExtension(filenameReports).isEmpty())
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
		public FormValidation doCheckFilenameSaveSession(
				@QueryParameter("filenameLoadSession") final String filenameLoadSession,
				@QueryParameter("filenameSaveSession") final String filenameSaveSession) {
			// Contains just the name of the session (without workspace path and extension)
			String cleanFilenameLoadSession = null;
			if(workspace != null) {
				cleanFilenameLoadSession = filenameLoadSession
						.replace(workspace.getRemote(), "") // Remove workspace path
						.replaceFirst("\\\\", "") // Remove separator after workspace path if windows
						.replaceFirst("/", ""); // Remove separator after workspace path if Unix
					
				if(!cleanFilenameLoadSession.isEmpty() && 
						(filenameSaveSession.equals(cleanFilenameLoadSession) 
								|| filenameSaveSession.equals(cleanFilenameLoadSession.replace(FILE_SESSION_EXTENSION, ""))) )
					return FormValidation.error("The saved session filename is the same of the loaded session filename.");
			}
			
			if(!filenameLoadSession.isEmpty())
				return FormValidation.warning("A session is loaded, so it's not necessary to save session");
			
			if(!FilenameUtils.getExtension(filenameSaveSession).isEmpty())
				return FormValidation.warning("A file extension is not necessary. A default file extension will be added (.session)");
			return FormValidation.ok();
		}
		
		/**
		 * List model to choose the alert report format
		 * 
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillChosenFormatsItems() {
			ListBoxModel items = new ListBoxModel();
			for(String format: mapFormatReport.keySet()) {
				items.add(format);
			}
			return items;
		}
		
		/**
		 * List model to choose the tool used (normally, it should be the ZAProxy tool).
		 * 
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillToolUsedItems() {
			ListBoxModel items = new ListBoxModel();
			for(ToolDescriptor<?> desc : ToolInstallation.all()) {
				for (ToolInstallation tool : desc.getInstallations()) {
					items.add(tool.getName());
				}
			}
			return items;
		}
		
		/**
		 * List model to choose the policy file to use by ZAProxy scan. It's called on the remote machine (if present)
		 * to load all policy files in the ZAP default dir of the build's machine.
		 * 
		 * @param zapDefaultDir A string that represents an absolute path to the directory that ZAP uses.
		 * @return a {@link ListBoxModel}. It can be empty if zapDefaultDir doesn't contain any policy file.
		 */		
		public ListBoxModel doFillChosenPolicyItems(@QueryParameter String zapDefaultDir) {			
			ListBoxModel items = new ListBoxModel();
			
			// No workspace before the first build, so workspace is null
			if(workspace != null) {
				File[] listFiles = {};
					try {
						listFiles = workspace.act(new PolicyFileCallable(zapDefaultDir));
					} catch (IOException e) {
						// No listener because it's not during a build but it's on the job config page
						e.printStackTrace();
					} catch (InterruptedException e) {
						// No listener because it's not during a build but it's on the job config page
						e.printStackTrace();
					}
					
				items.add(""); // To not load a policy file, add a blank choice
				
				// Add policy files to the list, without their extension
				for(int i = 0; i < listFiles.length; i++) {
					items.add(FilenameUtils.getBaseName(listFiles[i].getName()));
				}
			}
		
			return items;
		}
		
		/**
		 * List model to choose the ZAP session to use. It's called on the remote machine (if present)
		 * to load all session files in the build's workspace.
		 * 
		 * @return a {@link ListBoxModel}. It can be empty if the workspace doesn't contain any ZAP sessions.
		 * @throws InterruptedException 
		 * @throws IOException 
		 */
		public ListBoxModel doFillFilenameLoadSessionItems() throws IOException, InterruptedException {
			ListBoxModel items = new ListBoxModel();
			
			// No workspace before the first build, so workspace is null
			if(workspace != null) {
				Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {
					private static final long serialVersionUID = 1328740269013881941L;
	
					public Collection<String> invoke(File f, VirtualChannel channel) {
						
						// List all files with FILE_SESSION_EXTENSION on the machine where the workspace is located
						Collection<File> colFiles = FileUtils.listFiles(f,
								FileFilterUtils.suffixFileFilter(FILE_SESSION_EXTENSION),
								TrueFileFilter.INSTANCE);
						
						Collection<String> colString = new ArrayList<String>();
						
						// "Transform" File into String
						for (File file : colFiles) {
							colString.add(file.getAbsolutePath());
							// The following line is to remove the full path to the workspace,
							// keep just the relative path to the session
							//colString.add(file.getAbsolutePath().replace(workspace.getRemote() + File.separatorChar, ""));
						}
						return colString;
					}
	
					@Override
					public void checkRoles(RoleChecker checker) throws SecurityException {
						// Nothing to do
					}
				});
			
				items.add(""); // To not load a session, add a blank choice
				
				for (String s : sessionsInString) {
					items.add(s);
				}
			}
			
			return items;
		}
	}
	
	/**
	 * This class allows to search all ZAP policy files in the ZAP default dir of the remote machine
	 * (or local machine if there is no remote machine). It's used in the plugin configuration page
	 * to fill the list of policy files and choose one of them.  
	 * 
	 * @author ludovic.roucoux
	 *
	 */
	private static class PolicyFileCallable implements FileCallable<File[]> {
		private static final long serialVersionUID = 1328740269013881941L;
		
		private String zapDefaultDir;
		
		public PolicyFileCallable(String zapDefaultDir) {
			this.zapDefaultDir = zapDefaultDir;
		}

		public File[] invoke(File f, VirtualChannel channel) {
			File[] listFiles = {};
			
			Path pathPolicyDir = Paths.get(zapDefaultDir, NAME_POLICIES_DIR_ZAP);
			
			if(Files.isDirectory(pathPolicyDir)) {
				File zapPolicyDir = new File(zapDefaultDir, NAME_POLICIES_DIR_ZAP);
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
				listFiles = zapPolicyDir.listFiles(policyFilter);
			}
			return listFiles;
		}
	
		@Override
		public void checkRoles(RoleChecker checker) throws SecurityException {
			// Nothing to do
		}
	}
	
	/**
	 * This class allows to launch a method on a remote machine (if there is, otherwise, on a local machine).
	 * The method launched is to wait the complete initialization of ZAProxy.
	 * 
	 * @author ludovic.roucoux
	 *
	 */
	private static class WaitZAProxyInitCallable implements FileCallable<Void> {

		private static final long serialVersionUID = -313398999885177679L;
		
		private ZAProxy zaproxy; 
		private BuildListener listener;
		
		public WaitZAProxyInitCallable(ZAProxy zaproxy, BuildListener listener) {
			this.zaproxy = zaproxy;
			this.listener = listener;
		}

		@Override
		public Void invoke(File f, VirtualChannel channel) {
			zaproxy.waitForSuccessfulConnectionToZap(zaproxy.timeoutInSec, listener);
			return null;
		}
		
		@Override
		public void checkRoles(RoleChecker checker) throws SecurityException {
			// Nothing to do
		}
	}
}
