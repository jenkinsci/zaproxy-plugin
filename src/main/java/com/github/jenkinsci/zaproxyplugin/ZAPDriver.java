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

package com.github.jenkinsci.zaproxyplugin;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang.NullArgumentException;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.github.jenkinsci.zaproxyplugin.report.ZAPReport;
import com.github.jenkinsci.zaproxyplugin.report.ZAPReportCollection;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.Proc;
import hudson.model.AbstractBuild;
import hudson.model.AbstractDescribableImpl;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.EnvironmentSpecific;
import hudson.model.JDK;
import hudson.model.Node;
import hudson.remoting.VirtualChannel;
import hudson.slaves.NodeSpecific;
import hudson.slaves.SlaveComputer;
import hudson.tools.ToolDescriptor;
import hudson.tools.ToolInstallation;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;

/*
 * code clean up, formatting, readability, constancy throughout plugin and with the zap api added a name for context, check to make sure that the context does not already exist removed target url, added 'starting point', include in context removed old/inaccurate information from pom, and updated api calls accordingly added functionality to zap proxy builder to wait for the zap process to end before closing because we need to to wait for zap to cleanly shutdown which it
 * currently does not do, you also cannot modify the function wait for successful connection to be wait for successful disconnect because once the shutdown is sent, the socket cannot be polled anymore :/
 */

/**
 * Contains methods to start and execute ZAPDriver. Members variables are bind to the config.jelly placed to com.github.jenkinsci.zaproxyplugin.ZAPDriver
 *
 * @author Ludovic Roucoux
 * @author Johann Ollivier-Lapeyre
 * @author Thilina Madhusanka
 * @author Abdellah Azougarh
 * @author Goran Sarenkapa
 * @author Mostafa AbdelMoez
 * @author Tanguy de Lignières
 *
 * @see <a href= "https://github.com/zaproxy/zap-api-java/tree/master/subprojects/zap-clientapi"> [JAVA] Client API</a> The pom should show the artifact being from maven central.
 */
public class ZAPDriver extends AbstractDescribableImpl<ZAPDriver> implements Serializable {

    private static final long serialVersionUID = 3381268691497579059L;

    private static final String API_KEY = "ZAPROXY-PLUGIN";

    /* Folder names and file extensions */
    private static final String FILE_POLICY_EXTENSION = ".policy";
    private static final String FILE_SESSION_EXTENSION = ".session";
    private static final String FILE_AUTH_SCRIPTS_JS_EXTENSION = ".js";
    private static final String FILE_AUTH_SCRIPTS_ZEST_EXTENSION = ".zst";
    private static final String FILE_PLUGIN_EXTENSION = ".zap";
    private static final String NAME_PLUGIN_DIR_ZAP = "plugin";
    static final String NAME_POLICIES_DIR_ZAP = "policies";
    private static final String NAME_SCRIPTS_DIR_ZAP = "scripts";
    private static final String NAME_AUTH_SCRIPTS_DIR_ZAP = "authentication";
    private static final String NAME_REPORT_DIR = "reports";

    private static final String FORM_BASED = "FORM_BASED";
    private static final String SCRIPT_BASED = "SCRIPT_BASED";

    /* Command Line Options - Not exposed through the API */
    private static final String CMD_LINE_DIR = "-dir";
    private static final String CMD_LINE_HOST = "-host";
    private static final String CMD_LINE_PORT = "-port";
    private static final String CMD_LINE_DAEMON = "-daemon";
    private static final String CMD_LINE_CONFIG = "-config";
    private static final String CMD_LINE_API_KEY = "api.key";

    /* ZAP executable files */
    private static final String ZAP_PROG_NAME_BAT = "zap.bat";
    private static final String ZAP_PROG_NAME_SH = "zap.sh";

    private static final int TREAD_SLEEP = 5000;

    private static final String ZAP_PLUGIN_EXPORT_REPORT = "exportreport";
    private static final String ZAP_PLUGIN_JIRA_ISSUE_CREATOR = "jiraIssueCreater";
    //private static final String ZAP_PLUGIN_REGEX_EXPORT_REPORT = "\\Qexportreport-\\E.*\\Q.zap\\E";
    //private static final String ZAP_PLUGIN_REGEX_JIRA_ISSUE_CREATOR = "\\QjiraIssueCreater-\\E.*\\Q.zap\\E";

    /* ZAP Export Report Plugin Formats */
    private static final String DEFAULT_REPORT = "DEFAULT_REPORT";
    private static final String EXPORT_REPORT = "EXPORT_REPORT";
    private static final String EXPORT_REPORT_FORMAT_XML = "xml";
    private static final String EXPORT_REPORT_FORMAT_XHTML = "xhtml";
    private static final String EXPORT_REPORT_FORMAT_JSON = "json";
    
    @DataBoundConstructor
    public ZAPDriver(boolean autoInstall, String toolUsed, String zapHome, String jdk, int timeout,
            String zapSettingsDir,
            boolean autoLoadSession, String loadSession, String sessionFilename,
            String contextName, String includedURL, String excludedURL,
            boolean authMode, String username, String password, String loggedInIndicator, String authMethod,
            String loginURL, String usernameParameter, String passwordParameter, String extraPostData,
            String authScript, String protectedPages, List<ZAPAuthScriptParam> authScriptParams,
            String targetURL,
            boolean spiderScanURL, boolean spiderScanRecurse, boolean spiderScanSubtreeOnly, int spiderScanMaxChildrenToCrawl,
            boolean ajaxSpiderURL, boolean ajaxSpiderInScopeOnly,
            boolean activeScanURL, boolean activeScanRecurse, String activeScanPolicy,
            boolean generateReports, String selectedReportMethod, boolean deleteReports, String reportFilename,
            List<String> selectedReportFormats,
            List<String> selectedExportFormats,
            String exportreportTitle, String exportreportBy, String exportreportFor, String exportreportScanDate, String exportreportReportDate, String exportreportScanVersion, String exportreportReportVersion, String exportreportReportDescription,
            boolean exportreportAlertHigh, boolean exportreportAlertMedium, boolean exportreportAlertLow, boolean exportreportAlertInformational,
            boolean exportreportCWEID, boolean exportreportWASCID, boolean exportreportDescription, boolean exportreportOtherInfo, boolean exportreportSolution, boolean exportreportReference, boolean exportreportRequestHeader, boolean exportreportResponseHeader, boolean exportreportRequestBody, boolean exportreportResponseBody,
            boolean jiraCreate, String jiraProjectKey, String jiraAssignee, boolean jiraAlertHigh, boolean jiraAlertMedium, boolean jiraAlertLow, boolean jiraFilterIssuesByResourceType,
            List<ZAPCmdLine> cmdLinesZAP) {

        /* Startup */
        this.autoInstall = autoInstall;
        this.toolUsed = toolUsed;
        this.zapHome = zapHome;
        this.jdk = jdk;
        this.timeout = timeout;

        /* ZAP Settings */
        this.zapSettingsDir = zapSettingsDir;

        /* Session Management */
        this.autoLoadSession = autoLoadSession;
        this.loadSession = loadSession;
        this.sessionFilename = sessionFilename;

        /* Session Properties */
        this.contextName = contextName;
        this.includedURL = includedURL;
        this.excludedURL = excludedURL;

        /* Session Properties >> Authentication */
        this.authMode = authMode;
        this.username = username;
        this.password = password;
        this.loggedInIndicator = loggedInIndicator;
        this.authMethod = authMethod;

        /* Session Properties >> Form-Based Authentication */
        this.loginURL = loginURL;
        this.usernameParameter = usernameParameter;
        this.passwordParameter = passwordParameter;
        this.extraPostData = extraPostData;

        /* Session Properties >> Script-Based Authentication */
        this.authScript = authScript;
        this.protectedPages = protectedPages;
        this.authScriptParams = authScriptParams != null ? new ArrayList<ZAPAuthScriptParam>(authScriptParams) : new ArrayList<ZAPAuthScriptParam>();

        /* Attack Mode */
        this.targetURL = targetURL;

        /* Attack Mode >> Spider Scan */
        this.spiderScanURL = spiderScanURL;
        this.spiderScanRecurse = spiderScanRecurse;
        this.spiderScanSubtreeOnly = spiderScanSubtreeOnly;
        this.spiderScanMaxChildrenToCrawl = spiderScanMaxChildrenToCrawl;

        /* Attack Mode >> AJAX Spider */
        this.ajaxSpiderURL = ajaxSpiderURL;
        this.ajaxSpiderInScopeOnly = ajaxSpiderInScopeOnly;

        /* Attack Mode >> Active Scan */
        this.activeScanURL = activeScanURL;
        this.activeScanRecurse = activeScanRecurse;
        this.activeScanPolicy = activeScanPolicy;

        /* Finalize Run */

        /* Finalize Run >> Generate Report(s) */
        this.generateReports = generateReports;
        this.selectedReportMethod = selectedReportMethod;
        this.deleteReports = deleteReports;
        this.reportFilename = reportFilename;
        /* Finalize Run >> Generate Report(s) >> ZAP Default */
        this.selectedReportFormats = selectedReportFormats != null ? new ArrayList<String>(selectedReportFormats) : new ArrayList<String>();
        /* Finalize Run >> Generate Report(s) >> Export Report */
        this.selectedExportFormats = selectedExportFormats != null ? new ArrayList<String>(selectedExportFormats) : new ArrayList<String>();
        this.exportreportTitle = exportreportTitle;
        this.exportreportBy = exportreportBy;
        this.exportreportFor = exportreportFor;
        this.exportreportScanDate = exportreportScanDate;
        this.exportreportReportDate = exportreportReportDate;
        this.exportreportScanVersion = exportreportScanVersion;
        this.exportreportReportVersion = exportreportReportVersion;
        this.exportreportReportDescription = exportreportReportDescription;
        this.exportreportAlertHigh = exportreportAlertHigh;
        this.exportreportAlertMedium = exportreportAlertMedium;
        this.exportreportAlertLow = exportreportAlertLow;
        this.exportreportAlertInformational = exportreportAlertInformational;
        this.exportreportCWEID = exportreportCWEID;
        this.exportreportWASCID = exportreportWASCID;
        this.exportreportDescription = exportreportDescription;
        this.exportreportOtherInfo = exportreportOtherInfo;
        this.exportreportSolution = exportreportSolution;
        this.exportreportReference = exportreportReference;
        this.exportreportRequestHeader = exportreportRequestHeader;
        this.exportreportResponseHeader = exportreportResponseHeader;
        this.exportreportRequestBody = exportreportRequestBody;
        this.exportreportResponseBody = exportreportResponseBody;

        /* Finalize Run >> Create JIRA Issue(s) */
        this.jiraCreate = jiraCreate;
        this.jiraProjectKey = jiraProjectKey;
        this.jiraAssignee = jiraAssignee;
        this.jiraAlertHigh = jiraAlertHigh;
        this.jiraAlertMedium = jiraAlertMedium;
        this.jiraAlertLow = jiraAlertLow;
        this.jiraFilterIssuesByResourceType = jiraFilterIssuesByResourceType;
        /* Other */
        this.cmdLinesZAP = cmdLinesZAP != null ? new ArrayList<ZAPCmdLine>(cmdLinesZAP) : new ArrayList<ZAPCmdLine>();

        System.out.println(this.toString());
    }

    /**
     * Evaluated values will return null, this is printed to console on save
     * @return
     */
    @Override
    public String toString() {
        String s = "";
        s += "Admin Configurations\n";
        s += "-------------------------------------------------------\n";
        s += "zapHost [" + zapHost + "]\n";
        s += "zapPort [" + zapPort + "]\n";
        s += "autoInstall [" + autoInstall + "]\n";
        s += "toolUsed [" + toolUsed + "]\n";
        s += "zapHome [" + zapHome + "]\n";
        s += "jdk [" + jdk + "]\n";
        s += "timeout [" + timeout + "]\n";
        s += "\n";
        s += "ZAP Settings\n";
        s += "-------------------------------------------------------\n";
        s += "zapSettingsDir [" + zapSettingsDir + "]\n";
        s += "\n";
        s += "Load Session\n";
        s += "-------------------------------------------------------\n";
        s += "autoLoadSession [" + autoLoadSession + "]\n";
        s += "loadSession [" + loadSession + "]\n";
        s += "sessionFilename [" + sessionFilename + "]\n";
        s += "\n";
        s += "Session Properties\n";
        s += "-------------------------------------------------------\n";
        s += "contextName [" + contextName + "]\n";
        s += "includedURL [" + includedURL + "]\n";
        s += "excludedURL [" + excludedURL + "]\n";
        s += "\n";
        s += "Session Properties >> Authentication\n";
        s += "-------------------------------------------------------\n";
        s += "authMode [" + authMode + "]\n";
        s += "username [" + username + "]\n";
        s += "loggedInIndicator [" + loggedInIndicator + "]\n";
        s += "authMethod [" + authMethod + "]\n";
        s += "Session Properties >> Form-Based Authentication\n";
        s += "loginURL [" + loginURL + "]\n";
        s += "usernameParameter [" + usernameParameter + "]\n";
        s += "passwordParameter [" + passwordParameter + "]\n";
        s += "extraPostData [" + extraPostData + "]\n";
        s += "Session Properties >> Script-Based Authentication\n";
        s += "authScript [" + authScript + "]\n";
        s += "\n";
        s += "Attack Modes\n";
        s += "-------------------------------------------------------\n";
        s += "targetURL [" + targetURL + "]\n";
        s += "\n";
        s += "Attack Modes >> Spider Scan\n";
        s += "-------------------------------------------------------\n";
        s += "spiderScanURL [" + spiderScanURL + "]\n";
        s += "spiderRecurse [" + spiderScanRecurse + "]\n";
        s += "spiderSubtreeOnly [" + spiderScanSubtreeOnly + "]\n";
        s += "spiderMaxChildrenToCrawl [" + spiderScanMaxChildrenToCrawl + "]\n";
        s += "\n";
        s += "Attack Modes >> AJAX Spider\n";
        s += "-------------------------------------------------------\n";
        s += "ajaxSpiderURL [" + ajaxSpiderURL + "]\n";
        s += "ajaxSpiderInScopeOnly [" + ajaxSpiderInScopeOnly + "]\n";
        s += "\n";
        s += "Attack Modes >> Active Scan\n";
        s += "-------------------------------------------------------\n";
        s += "activeScanURL [" + activeScanURL + "]\n";
        s += "activeScanPolicy [" + activeScanPolicy + "]\n";
        s += "activeScanRecurse [" + activeScanRecurse + "]\n";
        s += "\n";
        s += "Finalize Run\n";
        s += "-------------------------------------------------------\n";
        s += "\n";
        s += "Finalize Run >> Generate Report(s)\n";
        s += "-------------------------------------------------------\n";
        s += "generateReports [" + generateReports + "]\n";
        s += "selectedReportMethod [" + selectedReportMethod + "]\n";
        s += "deleteReports [" + deleteReports + "]\n";
        s += "reportFilename [" + reportFilename + "]\n";
        s += "selectedReportFormats [" + selectedReportFormats + "]\n";
        s += "selectedExportFormats [" + selectedExportFormats + "]\n";
        s += "exportreportTitle [" + exportreportTitle + "]\n";
        s += "exportreportBy [" + exportreportBy + "]\n";
        s += "exportreportFor [" + exportreportFor + "]\n";
        s += "exportreportScanDate [" + exportreportScanDate + "]\n";
        s += "exportreportReportDate [" + exportreportReportDate + "]\n";
        s += "exportreportScanVersion [" + exportreportScanVersion + "]\n";
        s += "exportreportReportVersion [" + exportreportReportVersion + "]\n";
        s += "exportreportReportDescription [" + exportreportReportDescription + "]\n";
        s += "exportreportAlertHigh [" + exportreportAlertHigh + "]\n";
        s += "exportreportAlertMedium [" + exportreportAlertMedium + "]\n";
        s += "exportreportAlertLow [" + exportreportAlertLow + "]\n";
        s += "exportreportAlertInformational [" + exportreportAlertInformational + "]\n";
        s += "exportreportCWEID [" + exportreportCWEID + "]\n";
        s += "exportreportWASCID [" + exportreportWASCID + "]\n";
        s += "exportreportDescription [" + exportreportDescription + "]\n";
        s += "exportreportOtherInfo [" + exportreportOtherInfo + "]\n";
        s += "exportreportSolution [" + exportreportSolution + "]\n";
        s += "exportreportReference [" + exportreportReference + "]\n";
        s += "exportreportRequestHeader [" + exportreportRequestHeader + "]\n";
        s += "exportreportResponseHeader [" + exportreportResponseHeader + "]\n";
        s += "exportreportRequestBody [" + exportreportRequestBody + "]\n";
        s += "exportreportResponseBody [" + exportreportResponseBody + "]\n";
        s += "\n";
        s += "Finalize Run >> Create JIRA Issue(s)\n";
        s += "-------------------------------------------------------\n";
        s += "jiraCreate [" + jiraCreate + "]\n";
        s += "jiraBaseURL [" + jiraBaseURL + "]\n";
        s += "jiraUsername [" + jiraUsername + "]\n";
        s += "jiraProjectKey [" + jiraProjectKey + "]\n";
        s += "jiraAssignee [" + jiraAssignee + "]\n";
        s += "jiraAlertHigh [" + jiraAlertHigh + "]\n";
        s += "jiraAlertMedium [" + jiraAlertMedium + "]\n";
        s += "jiraAlertLow [" + jiraAlertLow + "]\n";
        s += "jiraFilterIssuesByResourceType[" + jiraFilterIssuesByResourceType + "]\n";
        return s;
    }

    /**
     * Test if the authentication mode types names match (for marking the radio button).
     *
     * @param testTypeName
     *            of TYPE String DESC: The String representation of the test type
     * @return Whether or not the test type string matches.
     */
    public String isAuthMethod(String testTypeName) {
        return this.authMethod.equalsIgnoreCase(testTypeName) ? "true" : "";
    }

    /**
     *
     *
     * @param testTypeName
     *            of TYPE String DESC: The String representation of the test type
     * @return Whether or not the test type string matches.
     */
    public String isSelectedReportMethod(String testTypeName) {
        return this.selectedReportMethod.equalsIgnoreCase(testTypeName) ? "true" : "";
    }

    /**
     * Get the ZAP_HOME setup by Custom Tools Plugin or already present on the build's machine.
     *
     * @param build
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @return the installed tool location, without zap.bat or zap.sh at the end
     * @throws InterruptedException
     * @throws IOException
     * @see <a href= "https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk"> https://groups.google.com/forum/#!topic/jenkinsci-dev/RludxaYjtDk </a>
     */
    private String retrieveZapHomeWithToolInstall(AbstractBuild<?, ?> build, BuildListener listener) throws IOException, InterruptedException {

        EnvVars env = null;
        Node node = null;
        String installPath = null;

        if (autoInstall) {
            env = build.getEnvironment(listener);
            node = build.getBuiltOn();
            for (ToolDescriptor<?> desc : ToolInstallation.all())
                for (ToolInstallation tool : desc.getInstallations())
                    if (tool.getName().equals(this.toolUsed)) {
                        if (tool instanceof NodeSpecific) tool = (ToolInstallation) ((NodeSpecific<?>) tool).forNode(node, listener);
                        if (tool instanceof EnvironmentSpecific) tool = (ToolInstallation) ((EnvironmentSpecific<?>) tool).forEnvironment(env);
                        installPath = tool.getHome();

                        return installPath;
                    }
        }
        else installPath = build.getEnvironment(listener).get(this.zapHome);
        return installPath;
    }

    /**
     * Return the ZAP program name with separator prefix (\zap.bat or /zap.sh) depending of the build node and the OS.
     *
     * @param build
     * @return the ZAProxy program name with separator prefix (\zap.bat or /zap.sh)
     * @throws IOException
     * @throws InterruptedException
     */
    private String getZAPProgramNameWithSeparator(AbstractBuild<?, ?> build) throws IOException, InterruptedException {
        Node node = build.getBuiltOn();
        String zapProgramName = "";

        /* Append zap program following Master/Slave and Windows/Unix */
        if ("".equals(node.getNodeName())) { // Master
            if (File.pathSeparatorChar == ':') zapProgramName = "/" + ZAP_PROG_NAME_SH;
            else zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
        }
        else if ("Unix".equals(((SlaveComputer) node.toComputer()).getOSDescription())) zapProgramName = "/" + ZAP_PROG_NAME_SH;
        else zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
        return zapProgramName;
    }

//    private File[] listFilesMatching(File root, String regex) {
//        if (!root.isDirectory()) throw new IllegalArgumentException(root + " is no directory.");
//        final Pattern p = Pattern.compile(regex); // careful: could also throw an exception!
//        return root.listFiles(new FileFilter() {
//            @Override
//            public boolean accept(File file) {
//                return p.matcher(file.getName()).matches();
//            }
//        });
//    }

    /**
     * Verify parameters of the build setup are correct (null, empty, negative ...)
     *
     * @param build
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @throws InterruptedException
     * @throws IOException
     * @throws Exception
     *             throw an exception if a parameter is invalid.
     */
    private void checkParams(AbstractBuild<?, ?> build, BuildListener listener) throws IllegalArgumentException, IOException, InterruptedException {
        zapProgram = retrieveZapHomeWithToolInstall(build, listener);
        Utils.loggerMessage(listener, 0, "[{0}] PLUGIN VALIDATION (PLG), VARIABLE VALIDATION AND ENVIRONMENT INJECTOR EXPANSION (EXP)", Utils.ZAP);

        if (this.zapProgram == null || this.zapProgram.isEmpty()) throw new IllegalArgumentException("ZAP PATH IS MISSING, PROVIDED [ " + this.zapProgram + " ]");
        else Utils.loggerMessage(listener, 1, "ZAP PATH = [ {0} ]", this.zapProgram);

        /* System Environment and Build Environment variables will be expanded already, the following step will expand Environment Injector variables. Note: cannot be expanded in pre-build step. */
        EnvVars envVars = build.getEnvironment(listener);

        this.evaluatedZapHost = envVars.expand(this.evaluatedZapHost);
        if (this.evaluatedZapHost == null || this.evaluatedZapHost.isEmpty()) throw new IllegalArgumentException("ZAP HOST IS MISSING, PROVIDED [ " + this.evaluatedZapHost + " ]");
        else Utils.loggerMessage(listener, 1, "(EXP) HOST = [ {0} ]", this.evaluatedZapHost);

        this.evaluatedZapPort = Integer.parseInt(envVars.expand(String.valueOf(this.evaluatedZapPort)));
        if (this.evaluatedZapPort < 0) throw new IllegalArgumentException("ZAP PORT IS LESS THAN 0, PROVIDED [ " + this.evaluatedZapPort + " ]");
        else Utils.loggerMessage(listener, 1, "(EXP) PORT = [ {0} ]", String.valueOf(this.evaluatedZapPort));

        this.evaluatedZapSettingsDir = envVars.expand(this.evaluatedZapSettingsDir);
        if (this.evaluatedZapSettingsDir == null || this.evaluatedZapSettingsDir.isEmpty()) throw new IllegalArgumentException("ZAP SETTINGS DIRECTORY IS MISSING, PROVIDED [ " + this.evaluatedZapSettingsDir + " ]");
        else Utils.loggerMessage(listener, 1, "(EXP) ZAP SETTINGS DIRECTORY = [ {0} ]",this. evaluatedZapSettingsDir);

        this.evaluatedSessionFilename = envVars.expand(this.evaluatedSessionFilename);
        Utils.loggerMessage(listener, 1, "(EXP) SESSION FILENAME = [ {0} ]", this.evaluatedSessionFilename);

        this.evaluatedContextName = envVars.expand(this.evaluatedContextName);
        if (this.evaluatedContextName == null || this.evaluatedContextName.isEmpty()) this.evaluatedContextName = "Jenkins Default Context";
        else Utils.loggerMessage(listener, 1, "(EXP) CONTEXT NAME = [ {0} ]", this.evaluatedContextName);

        this.evaluatedIncludedURL = envVars.expand(this.evaluatedIncludedURL);
        if (this.evaluatedIncludedURL == null || this.evaluatedIncludedURL.isEmpty()) throw new IllegalArgumentException("INCLUDE IN CONTEXT IS MISSING, PROVIDED [ " + this.evaluatedIncludedURL + " ]");
        else Utils.loggerMessage(listener, 1, "(EXP) INCLUDE IN CONTEXT = [ {0} ]", this.evaluatedIncludedURL.trim().replace("\n", ", "));

        this.evaluatedExcludedURL = envVars.expand(this.evaluatedExcludedURL);
        Utils.loggerMessage(listener, 1, "(EXP) EXCLUDE FROM CONTEXT = [ {0} ]", this.evaluatedExcludedURL.trim().replace("\n", ", "));

        this.evaluatedTargetURL = envVars.expand(this.evaluatedTargetURL);
        if ((this.evaluatedTargetURL == null || this.evaluatedTargetURL.isEmpty()) && !this.startZAPFirst) throw new IllegalArgumentException("STARTING POINT (URL) IS MISSING, PROVIDED [ " + this.evaluatedTargetURL + " ]");
        else Utils.loggerMessage(listener, 1, "(EXP) STARTING POINT (URL) = [ {0} ]", this.evaluatedTargetURL);

        if (this.generateReports) {
            this.evaluatedReportFilename = envVars.expand(this.evaluatedReportFilename);
            if ((this.evaluatedReportFilename == null || this.evaluatedReportFilename.isEmpty()) && !this.startZAPFirst) throw new IllegalArgumentException("REPORT FILENAME IS MISSING, PROVIDED [ " + this.evaluatedReportFilename + " ]");
            else Utils.loggerMessage(listener, 1, "(EXP) REPORT FILENAME = [ {0} ]", this.evaluatedReportFilename);

            if (selectedReportMethod.equals(DEFAULT_REPORT)) {
                if (this.selectedReportFormats.size() == 0) throw new NullArgumentException("GENERATE REPORTS IS CHECKED, DEFAULT REPORT FORMAT");
            }
            else if (selectedReportMethod.equals(EXPORT_REPORT)) {
                // File[] plugin = listFilesMatching(Paths.get(this.evaluatedZapSettingsDir, NAME_PLUGIN_DIR_ZAP).toFile(), ZAP_PLUGIN_REGEX_EXPORT_REPORT);
                // if (plugin.length > 0) {
                // Utils.loggerMessage(listener, 1, "(PLG) EXPORT REPORT PLUGIN HAS BEEN FOUND [ {0} ]", plugin[0].getName());
                if (this.selectedExportFormats.size() == 0) throw new NullArgumentException("GENERATE REPORTS IS CHECKED, EXPORT REPORT FORMAT");

                this.evaluatedExportreportTitle = envVars.expand(this.evaluatedExportreportTitle);
                if ((this.evaluatedExportreportTitle == null || this.evaluatedExportreportTitle.isEmpty()) && !this.startZAPFirst) throw new IllegalArgumentException("REPORT TITLE IS MISSING, PROVIDED [ " + this.evaluatedExportreportTitle + " ]");
                else Utils.loggerMessage(listener, 1, "(EXP) REPORT TITLE = [ {0} ]", this.evaluatedExportreportTitle);
                // }
                // else throw new NoSuchFileException("EXPORT REPORT PLUGIN COULD NOT BE FOUND");
            }
        }

        /* jiraCreate is enabled */
        if (this.jiraCreate) {
            // File[] plugin = listFilesMatching(Paths.get(this.evaluatedZapSettingsDir, NAME_PLUGIN_DIR_ZAP).toFile(), ZAP_PLUGIN_REGEX_JIRA_ISSUE_CREATOR);
            // if (plugin.length > 0) {
            // Utils.loggerMessage(listener, 1, "(PLG) JIRA ISSUE CREATOR PLUGIN HAS BEEN FOUND [ {0} ]", plugin[0].getName());

            /* Minimum : the url is needed */
            if (this.jiraBaseURL == null || this.jiraBaseURL.isEmpty()) throw new IllegalArgumentException("JIRA BASE URL IS MISSING, PROVIDED [ " + this.jiraBaseURL + " ]");
            else Utils.loggerMessage(listener, 1, "JIRA BASE URL = [ {0} ]", this.jiraBaseURL);

            /* the username can be empty */
            if (this.jiraUsername == null) throw new IllegalArgumentException("JIRA USERNAME IS MISSING, PROVIDED [ " + this.jiraUsername + " ]");
            else Utils.loggerMessage(listener, 1, "JIRA USERNAME = [ {0} ]", this.jiraUsername);

            /* the password can be empty */
            if (this.jiraPassword == null) throw new IllegalArgumentException("JIRA PASSWORD IS MISSING");
            else Utils.loggerMessage(listener, 1, "JIRA PASSWORD = [ OK ]");
            // }
            // else throw new NoSuchFileException("JIRA ISSUE CREATOR PLUGIN COULD NOT BE FOUND");
        }
        Utils.lineBreak(listener);
    }

    /**
     * Start ZAProxy using command line. It uses host and port configured in Jenkins admin mode and ZAPDriver program is launched in daemon mode (i.e without UI). ZAPDriver is started on the build's machine (so master machine or slave machine) thanks to {@link FilePath} object and {@link Launcher} object.
     *
     * @param build
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @param launcher
     *            of TYPE Launcher DESC: the object to launch a process locally or remotely
     * @throws InterruptedException
     * @throws IOException
     * @throws IllegalArgumentException
     */
    public Proc startZAP(AbstractBuild<?, ?> build, BuildListener listener, Launcher launcher) throws IllegalArgumentException, IOException, InterruptedException {
        this.getAvailableFormats(getDescriptor());

        checkParams(build, listener);

        FilePath ws = build.getWorkspace();
        if (ws == null) {
            Node node = build.getBuiltOn();
            if (node == null) throw new NullPointerException("No such build node: " + build.getBuiltOnStr());
            throw new NullPointerException("No workspace from node " + node + " which is computer " + node.toComputer() + " and has channel " + node.getChannel());
        }

        /* Contains the absolute path to ZAP program */
        FilePath zapPathWithProgName = new FilePath(ws.getChannel(), zapProgram + getZAPProgramNameWithSeparator(build));
        Utils.loggerMessage(listener, 0, "[{0}] CONFIGURE RUN COMMANDS for [ {1} ]", Utils.ZAP, zapPathWithProgName.getRemote());

        /* Command to start ZAProxy with parameters */
        List<String> cmd = new ArrayList<String>();
        cmd.add(zapPathWithProgName.getRemote());
        cmd.add(CMD_LINE_DAEMON);
        cmd.add(CMD_LINE_HOST);
        cmd.add(this.evaluatedZapHost);
        cmd.add(CMD_LINE_PORT);
        cmd.add(String.valueOf(this.evaluatedZapPort));
        cmd.add(CMD_LINE_CONFIG);
        cmd.add(CMD_LINE_API_KEY + "=" + API_KEY);

        /* Set the default directory used by ZAP if it's defined and if a scan is provided */
        if (this.activeScanURL && this.evaluatedZapSettingsDir != null && !this.evaluatedZapSettingsDir.isEmpty()) {
            cmd.add(CMD_LINE_DIR);
            cmd.add(this.evaluatedZapSettingsDir);
        }

        /* Adds command line arguments if it's provided */
        if (!this.evaluatedCmdLinesZap.isEmpty()) addZapCmdLine(cmd, this.evaluatedCmdLinesZap);

        EnvVars envVars = build.getEnvironment(listener);
        /* on Windows environment variables are converted to all upper case, but no such conversions are done on Unix, so to make this cross-platform, convert variables to all upper cases. */
        for (Map.Entry<String, String> e : build.getBuildVariables().entrySet())
            envVars.put(e.getKey(), e.getValue());
        FilePath workDir = new FilePath(ws.getChannel(), zapProgram);

        /* JDK choice */
        computeJdkToUse(build, listener, envVars);

        /* Launch ZAP process on remote machine (on master if no remote machine) */
        Utils.loggerMessage(listener, 0, "[{0}] EXECUTE LAUNCH COMMAND", Utils.ZAP);
        Proc proc = launcher.launch().cmds(cmd).envs(envVars).stdout(listener).pwd(workDir).start();

        /* Call waitForSuccessfulConnectionToZap(int, BuildListener) remotely */
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 0, "[{0}] INITIALIZATION [ START ]", Utils.ZAP);
        build.getWorkspace().act(new WaitZAPDriverInitCallable(listener, this));
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 0, "[{0}] INITIALIZATION [ SUCCESSFUL ]", Utils.ZAP);
        Utils.lineBreak(listener);
        return proc;
    }

    /**
     * Set the JDK to use to start ZAP.
     *
     * @param build
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @param env
     *            of TYPE EnvVars DESC: list of environment variables. Used to set the path to the JDK
     * @throws IOException
     * @throws InterruptedException
     */
    private void computeJdkToUse(AbstractBuild<?, ?> build, BuildListener listener, EnvVars env) throws IOException, InterruptedException {
        JDK jdkToUse = getJdkToUse(build.getProject());
        if (jdkToUse != null) {
            Computer computer = Computer.currentComputer();
            /* just in case we are not in a build */
            if (computer != null) jdkToUse = jdkToUse.forNode(computer.getNode(), listener);
            jdkToUse.buildEnvVars(env);
        }
    }

    /**
     * @return JDK to be used with this project.
     */
    private JDK getJdkToUse(AbstractProject<?, ?> project) {
        JDK jdkToUse = getJDK();
        if (jdkToUse == null) jdkToUse = project.getJDK();
        return jdkToUse;
    }

    /**
     * Add list of command line to the list in param
     *
     * @param list
     *            of TYPE List<String> DESC: the list to attach ZAP command line to
     */
    private void addZapCmdLine(List<String> list, ArrayList<ZAPCmdLine> cmdList) {
        for (ZAPCmdLine zapCmd : cmdList) {
            if (zapCmd.getCmdLineOption() != null && !zapCmd.getCmdLineOption().isEmpty()) list.add(zapCmd.getCmdLineOption());
            if (zapCmd.getCmdLineValue() != null && !zapCmd.getCmdLineValue().isEmpty()) list.add(zapCmd.getCmdLineValue());
        }
    }

    /**
     * Add list of authentication script parameters
     *
     * @param s
     *            stringbuilder to attach authentication script parameter
     */
    private void addZAPAuthScriptParam(ArrayList<ZAPAuthScriptParam> authScriptParams, StringBuilder s) throws UnsupportedEncodingException {
        for (ZAPAuthScriptParam authScriptParam : authScriptParams) {
            if (authScriptParam.getScriptParameterName() != null && !authScriptParam.getScriptParameterName().isEmpty()) s.append("&" + URLEncoder.encode(authScriptParam.getScriptParameterName(), "UTF-8") + "=");
            if (authScriptParam.getScriptParameterValue() != null && !authScriptParam.getScriptParameterValue().isEmpty()) s.append(URLEncoder.encode(authScriptParam.getScriptParameterValue(), "UTF-8").toString());
        }
    }

    /**
     * Wait for ZAP's initialization such that it is ready to use at the end of the method, otherwise catch the exception. If there is a remote machine, then this method will be launched there.
     *
     * @param timeout
     *            of TYPE int DESC: the time in seconds to try to connect to ZAP.
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display the log during the job execution in Jenkins
     * @see <a href= "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960"> [JAVA] Avoid sleep to wait ZAProxy initialization</a>
     */
    private void waitForSuccessfulConnectionToZap(BuildListener listener, int timeout) {
        int timeoutInMs = (int) TimeUnit.SECONDS.toMillis(timeout);
        int connectionTimeoutInMs = timeoutInMs;
        int pollingIntervalInMs = (int) TimeUnit.SECONDS.toMillis(1);
        boolean connectionSuccessful = false;
        long startTime = System.currentTimeMillis();
        Socket socket = null;
        do
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress(evaluatedZapHost, evaluatedZapPort), connectionTimeoutInMs);
                connectionSuccessful = true;
            }
        catch (SocketTimeoutException ignore) {
            listener.error(ExceptionUtils.getStackTrace(ignore));
            throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");

        }
        catch (IOException ignore) {
            /* Try again but wait some time first */
            try {
                Thread.sleep(pollingIntervalInMs);
            }
            catch (InterruptedException e) {
                listener.error(ExceptionUtils.getStackTrace(ignore));
                throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
            }

            long ellapsedTime = System.currentTimeMillis() - startTime;
            if (ellapsedTime >= timeoutInMs) {
                listener.error(ExceptionUtils.getStackTrace(ignore));
                throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
            }
            connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
        }
        finally {
            if (socket != null) try {
                socket.close();
            }
            catch (IOException e) {
                listener.error(ExceptionUtils.getStackTrace(e));
            }
        }
        while (!connectionSuccessful);
    }

    /**
     *
     * @param listener
     * @param clientApi
     * @param autoLoadSession
     * @param loadSession
     * @param sessionFilename
     * @param buildSuccess
     * @return
     * @throws ClientApiException
     */
    private boolean loadSession (BuildListener listener, ClientApi clientApi, boolean autoLoadSession, String loadSession, String sessionFilename, boolean buildSuccess) throws ClientApiException{
        if (autoLoadSession && loadSession != null && loadSession.length() != 0) {
            File sessionFile = new File(this.loadSession);
            Utils.loggerMessage(listener, 0, "[{0}] LOAD SESSION AT: [ {1} ]", Utils.ZAP, sessionFile.getAbsolutePath());

            /*
             * @class org.zaproxy.clientapi.gen.Core
             *
             * @method loadSession
             *
             * @param String apikey
             * @param String name
             *
             * @throws ClientApiException
             */
            clientApi.core.loadSession(API_KEY, sessionFile.getAbsolutePath());
        }
        else if (!autoLoadSession) {
            Utils.loggerMessage(listener, 0, "[{0}] SKIP SESSION LOADING", Utils.ZAP);
            if (sessionFilename == null || sessionFilename.isEmpty()) {
                buildSuccess = false;
                Utils.loggerMessage(listener, 0, "[{0}] PERSIST SESSION FAILURE, NO SESSION SPECIFIED", Utils.ZAP);
            }
        }
        else {
            buildSuccess = false;
            Utils.loggerMessage(listener, 0, "[{0}] LOAD SESSION FAILURE, NO SESSION SPECIFIED", Utils.ZAP);
        }
        return buildSuccess;
    }

    /**
     *
     * @param listener
     * @param workspace
     */
    private void deleteReports(BuildListener listener, FilePath workspace, String extensions, ArrayList<String> formats) {
        Utils.loggerMessage(listener, 1, "CLEARING WORKSPACE OF [ {0} ]", extensions);

        File folder = new File(workspace.getRemote());
        ArrayList<File> fList = new ArrayList<File>(Arrays.asList(folder.listFiles()));

        for (String format : formats)
            for (File file : fList)
                if (file.isFile() && file.getName().contains("." + format)) {
                    Utils.loggerMessage(listener, 2, "DELETED [ {0} ]", file.getName());
                    file.delete();
                }

        Utils.loggerMessage(listener, 1, "CLEARING WORKSPACE/{0} OF [ {1} ]", NAME_REPORT_DIR.toUpperCase(), extensions);
        Path p = Paths.get(workspace.getRemote(), NAME_REPORT_DIR);
        folder = p.toFile();
        if (folder.exists()) {
            fList = new ArrayList<File>(Arrays.asList(folder.listFiles()));

            for (String format : formats)
                for (File file : fList)
                    if (file.isFile() && file.getName().contains("." + format)) {
                        Utils.loggerMessage(listener, 2, "DELETED [ {0} ]", file.getName());
                        file.delete();
                    }
        }
    }

    /**
     * Generates security report for one format. Reports are saved into build's workspace.
     *
     * @param reportFormat
     *            of TYPE: ZAPJReport DESC: the format of the report
     * @param listener
     *            of TYPE: BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @param workspace
     *            of TYPE: FilePath DESC: a {@link FilePath} representing the build's workspace
     * @param clientApi
     *            of TYPE: ClientApi DESC: the ZAP client API to call method
     * @throws ClientApiException
     * @throws IOException
     */
    private void saveReport(BuildListener listener, ClientApi clientApi, FilePath workspace, ZAPReport reportFormat, String filename) throws IOException, ClientApiException {
        final String fullFileName = filename + "." + reportFormat.getFormat();
        File reportsFile = new File(workspace.getRemote(), fullFileName);
        FileUtils.writeByteArrayToFile(reportsFile, reportFormat.generateReport(clientApi, API_KEY));
        Utils.loggerMessage(listener, 1, "[ {0} ] SAVED TO [ {1} ]", reportFormat.getFormat().toUpperCase(), reportsFile.getAbsolutePath());
    }

    /**
     *
     * @param listener
     * @param clientApi
     * @param workspace
     * @param selectedFormats
     * @param reportFilename
     * @param sourceDetails
     * @param alertSeverity
     * @param alertDetails
     * @param buildSuccess
     * @return
     */
    private boolean exportReport(BuildListener listener, ClientApi clientApi, FilePath workspace, ArrayList<String> selectedFormats, String reportFilename, String sourceDetails, String alertSeverity, String alertDetails, boolean buildSuccess) {
        try {
            ArrayList<String> validFormats = new ArrayList<String>();
            ArrayList<String> apiFormats = new ArrayList<String>();
            Map<String, String> mapView = null;
            mapView = new HashMap<String, String>();
            if (API_KEY != null) mapView.put("apikey", API_KEY);
            ApiResponseList apiReponseFormats = (ApiResponseList) clientApi.callApi("exportreport", "view", "formats", mapView);
            Utils.loggerMessage(listener, 1, "EXPORT REPORT FORMAT CHECK [ TRUE ]");

            if (apiReponseFormats.getItems().size() > 0) for (int i = 0; i < apiReponseFormats.getItems().size(); i++) {
                ApiResponseElement apiFormat = (ApiResponseElement) apiReponseFormats.getItems().get(i);
                apiFormats.add(apiFormat.getValue());
            }

            for (String pluginFormat : selectedFormats)
                if (apiFormats.contains(pluginFormat)) {
                    Utils.loggerMessage(listener, 2, "[ {0} ] IS A VALID FORMAT", pluginFormat.toUpperCase());
                    validFormats.add(pluginFormat);
                }
                else Utils.loggerMessage(listener, 2, "[ {0} ] IS AN INVALID FORMAT", pluginFormat.toUpperCase());

            for (String format : validFormats)
                if (buildSuccess) {
                    Map<String, String> map = null;
                    map = new HashMap<String, String>();

                    final String fullFileName = reportFilename + "." + format;
                    Path p = Paths.get(workspace.getRemote(), NAME_REPORT_DIR);
                    File f = p.toFile();
                    if (!f.exists()) {
                        f.mkdir();
                    }
                    f = new File(p.toAbsolutePath().toString(), fullFileName);

                    if (API_KEY != null) map.put("apikey", API_KEY);
                    map.put("absolutePath", f.getAbsolutePath());
                    map.put("fileExtension", format);
                    map.put("sourceDetails", sourceDetails);
                    map.put("alertSeverity", alertSeverity);
                    map.put("alertDetails", alertDetails);

                    Utils.lineBreak(listener);
                    Utils.loggerMessage(listener, 1, "INITIALIZE EXPORT REPORT VARIABLES FOR [ {0} ] EXPORT", format.toUpperCase());
                    Utils.loggerMessage(listener, 2, "API KEY [ {0} ]", API_KEY);
                    Utils.loggerMessage(listener, 2, "ABSOLUTE PATH [ {0} ]", f.getAbsolutePath());
                    Utils.loggerMessage(listener, 2, "FILE EXTENSION [ .{0} ]", format);
                    Utils.loggerMessage(listener, 2, "SOURCE DETAILS [ {0} ]", sourceDetails);
                    Utils.loggerMessage(listener, 2, "ALERT SEVERITY [ {0} ]", alertSeverity);
                    Utils.loggerMessage(listener, 2, "ALERT DETAILS [ {0} ]", alertDetails);
                    Utils.lineBreak(listener);

                    /*
                     * @class org.zaproxy.clientapi.core.ClientApi
                     *
                     * @method callApi
                     *
                     * @param String component
                     * @param String type
                     * @param String method
                     * @param Map<String, String> params
                     *
                     * @throws ClientApiException
                     */
                    ApiResponseElement val = (ApiResponseElement) clientApi.callApi("exportreport", "action", "generate", map);
                    if (val.getValue().equals(ApiResponseElement.FAIL.getValue())) {
                        Utils.lineBreak(listener);
                        Utils.loggerMessage(listener, 0, "[{0}] EXPORT REPORT PLUGIN RETURNED STATUS [ FAIL ], BUILD RESULTING IN FAILURE", Utils.ZAP);
                        buildSuccess = false;
                    }
                    try {
                        Thread.sleep(TREAD_SLEEP);
                        Thread.sleep(TREAD_SLEEP);
                    }
                    catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
        }
        catch (ClientApiException e) {
            listener.getLogger().println(e.getMessage());
        }
        return buildSuccess;
    }

    /**
     *
     * @param listener
     * @param clientApi
     * @param jiraBaseURL
     * @param jiraUsername
     * @param jiraPassword
     * @param jiraProjectKey
     * @param jiraAssignee
     * @param jiraAlertHigh
     * @param jiraAlertMedium
     * @param jiraAlertLow
     * @param jiraFilterIssuesByResourceType
     */
    private void jiraCreate(BuildListener listener, ClientApi clientApi, String jiraBaseURL, String jiraUsername, String jiraPassword, String jiraProjectKey, String jiraAssignee, boolean jiraAlertHigh, boolean jiraAlertMedium, boolean jiraAlertLow, boolean jiraFilterIssuesByResourceType) {
        Map<String, String> map = null;
        map = new HashMap<String, String>();

        if (API_KEY != null) map.put("apikey", API_KEY);
        map.put("jiraBaseURL", jiraBaseURL);
        map.put("jiraUserName", jiraUsername);
        map.put("jiraPassword", jiraPassword);
        map.put("jiraProjectKey", jiraProjectKey);
        map.put("jiraAssignee", jiraAssignee);
        map.put("high", returnCheckedStatus(jiraAlertHigh));
        map.put("medium", returnCheckedStatus(jiraAlertMedium));
        map.put("low", returnCheckedStatus(jiraAlertLow));
        map.put("filterIssuesByResourceType", returnCheckedStatus(jiraFilterIssuesByResourceType));

        Utils.loggerMessage(listener, 1, "INITIALIZE JIRA VARIABLES", Utils.ZAP);
        Utils.loggerMessage(listener, 2, "API KEY [ {0} ]", API_KEY);
        Utils.loggerMessage(listener, 2, "BASE URL [ {0} ]", jiraBaseURL);
        Utils.loggerMessage(listener, 2, "USERNAME [ {0} ]", jiraUsername);
        Utils.loggerMessage(listener, 2, "PROJECT KEY [ {0} ]", jiraProjectKey);
        Utils.loggerMessage(listener, 2, "ASSIGNEE [ {0} ]", jiraAssignee);
        Utils.loggerMessage(listener, 2, "EXPORT HIGH ALERTS [ {0} ]", Boolean.toString(jiraAlertHigh).toUpperCase());
        Utils.loggerMessage(listener, 2, "EXPORT MEDIUM ALERTS [ {0} ]", Boolean.toString(jiraAlertMedium).toUpperCase());
        Utils.loggerMessage(listener, 2, "EXPORT LOW ALERTS [ {0} ]", Boolean.toString(jiraAlertLow).toUpperCase());
        Utils.loggerMessage(listener, 2, "FILTER BY RESOURCE TYPE [ {0} ]", Boolean.toString(jiraFilterIssuesByResourceType).toUpperCase());

        try {
            /*
             * @class org.zaproxy.clientapi.core.ClientApi
             *
             * @method callApi
             *
             * @param String component
             * @param String type
             * @param String method
             * @param Map<String, String> params
             *
             * @throws ClientApiException
             */
            clientApi.callApi("jiraIssueCreater", "action", "createJiraIssues", map);

        }
        catch (ClientApiException e) {
            listener.getLogger().println(e.getMessage());
        }
    }

    /**
     *
     * @param listener
     * @param clientApi
     * @param workspace
     * @param filename
     * @throws ClientApiException
     */
    private void persistSession (BuildListener listener, ClientApi clientApi, FilePath workspace, String filename) throws ClientApiException {
        if (filename != null && !filename.isEmpty()) {
            File sessionFile = new File(workspace.getRemote(), filename);
            Utils.loggerMessage(listener, 0, "[{0}] PERSIST SESSION TO: [ {1} ]", Utils.ZAP, sessionFile.getAbsolutePath());
            /* If the path does not exist, create it. */
            if (!sessionFile.getParentFile().exists()) sessionFile.getParentFile().mkdirs();

            /*
             * @class org.zaproxy.clientapi.gen.Core
             *
             * @method saveSession
             *
             * @param String apikey
             * @param String name
             * @param String overwrite
             *
             * @throws ClientApiException
             */
            clientApi.core.saveSession(API_KEY, sessionFile.getAbsolutePath(), "true");
        }
    }

    /**
     * Execute ZAPJ method following build's setup and stop ZAP at the end. Note: No param's to executeZAP method since they would also need to be accessible in builder, somewhat redundant.
     *
     * @param workspace
     *            of TYPE: FilePath DESC: a {@link FilePath} representing the build's workspace
     * @param listener
     *            of TYPE: BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @return of TYPE: boolean DESC: true if no exception is caught, false otherwise.
     * @throws NoSuchFileException 
     */
    public boolean executeZAP(BuildListener listener, FilePath workspace) {
        boolean buildSuccess = true;

        if (((this.generateReports) && this.selectedReportMethod.equals(EXPORT_REPORT)) || (this.jiraCreate)) {
            Utils.loggerMessage(listener, 0, "[{0}] PLUGIN SEARCH...", Utils.ZAP);
            // No workspace before the first build, so workspace is null
            if (workspace != null) {
                File[] listFiles = {};
                try {
                    listFiles = workspace.act(new PluginCallable(this.evaluatedZapSettingsDir));
                }
                catch (IOException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                catch (InterruptedException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                int count = 0;
                for (File listFile : listFiles) {
                    if (FilenameUtils.getBaseName(listFile.getName()).contains(ZAP_PLUGIN_EXPORT_REPORT) || FilenameUtils.getBaseName(listFile.getName()).contains(ZAP_PLUGIN_JIRA_ISSUE_CREATOR)) {
                        Utils.loggerMessage(listener, 1, "[ {0} ] PLUGIN HAS BEEN FOUND", FilenameUtils.getBaseName(listFile.getName()));
                        count++;
                    }
                }
                if (count == 0) {
                    Utils.loggerMessage(listener, 1, "REQUIRED PLUGIN(S) ARE MISSING");
                    buildSuccess = false;
                }
            }
            Utils.lineBreak(listener);
        }

        ClientApi clientApi = new ClientApi(this.evaluatedZapHost, this.evaluatedZapPort);

        try {
            /* LOAD SESSION */
            if (buildSuccess) {
                buildSuccess = loadSession(listener, clientApi, this.autoLoadSession, this.loadSession, this.sessionFilename, buildSuccess);
                Utils.lineBreak(listener);
            }

            if (buildSuccess) {
                /* SETUP CONTEXT  */
                this.contextId = setUpContext(listener, clientApi, this.evaluatedContextName, this.evaluatedIncludedURL, this.evaluatedExcludedURL);

                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] AUTHENTICATION ENABLED [ {1} ]", Utils.ZAP, String.valueOf(this.authMode).toUpperCase());
                Utils.loggerMessage(listener, 0, "[{0}] AUTHENTICATION MODE [ {1} ]", Utils.ZAP, this.authMethod.toUpperCase());
                Utils.lineBreak(listener);
                /* SETUP AUTHENICATION */
                if (this.authMode) if (this.authMethod.equals(FORM_BASED)) this.userId = setUpAuthentication(listener, clientApi, this.contextId, this.loginURL, this.username, this.password, this.loggedInIndicator, this.extraPostData, this.authMethod, this.usernameParameter, this.passwordParameter, null, null);
                else if (this.authMethod.equals(SCRIPT_BASED)) this.userId = setUpAuthentication(listener, clientApi, this.contextId, this.loginURL, this.username, this.password, this.loggedInIndicator, this.extraPostData, this.authMethod, null, null, this.authScript, this.authScriptParams);

                /* SETUP ATTACK MODES */
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] ATTACK MODE(S) INITIATED", Utils.ZAP);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] SPIDER SCAN ENABLED [ {1} ]", Utils.ZAP, String.valueOf(this.spiderScanURL).toUpperCase());
                spiderScanURL(listener, clientApi, this.spiderScanURL, this.evaluatedTargetURL, this.contextName, this.contextId, this.userId, this.authMode, this.spiderScanRecurse, this.spiderScanSubtreeOnly, this.spiderScanMaxChildrenToCrawl);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] AJAX SPIDER ENABLED [ {1} ]", Utils.ZAP, String.valueOf(this.ajaxSpiderURL).toUpperCase());
                ajaxSpiderURL(listener, clientApi, this.ajaxSpiderURL, this.evaluatedTargetURL, this.ajaxSpiderInScopeOnly);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] ACTIVE SCAN ENABLED [ {1} ]", Utils.ZAP, String.valueOf(this.activeScanURL).toUpperCase());
                activeScanURL(listener, clientApi, this.activeScanURL, this.evaluatedTargetURL, this.contextId, this.userId, this.authMode, this.activeScanPolicy, this.activeScanRecurse);

                /* CLEAR WORKSPACE  */
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] CLEAR WORKSPACE OF PREVIOUS REPORT(S) [ {1} ]", Utils.ZAP, Boolean.toString(this.deleteReports).toUpperCase());
                if (this.generateReports && this.deleteReports) deleteReports(listener, workspace, this.availableFormatsString, this.availableFormatsArray);
                else Utils.loggerMessage(listener, 1, "SKIP CLEARING WORKSPACE");

                /* GENERATE REPORTS  */
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] GENERATE REPORT(S) [ {1} ]", Utils.ZAP, String.valueOf(this.generateReports).toUpperCase());
                /* DEFAULT REPORT */
                if (this.generateReports)  if(this.selectedReportMethod.equals(DEFAULT_REPORT)) for (String format : this.selectedReportFormats) {
                    ZAPReport report = ZAPReportCollection.getInstance().getMapFormatReport().get(format);
                    saveReport(listener, clientApi, workspace, report, this.evaluatedReportFilename);
                }
                else if (this.selectedReportMethod.equals(EXPORT_REPORT)) {
                    String sourceDetails = this.evaluatedExportreportTitle + ";" + this.exportreportBy + ";" + this.exportreportFor + ";" + this.exportreportScanDate + ";" + this.exportreportReportDate + ";" + this.exportreportScanVersion + ";" + this.exportreportReportVersion + ";" + this.exportreportReportDescription;
                    String alertSeverity = returnBooleanCheckedStatus(this.exportreportAlertHigh) + ";" + returnBooleanCheckedStatus(this.exportreportAlertMedium) + ";" + returnBooleanCheckedStatus(this.exportreportAlertLow) + ";" + returnBooleanCheckedStatus(this.exportreportAlertInformational);
                    String alertDetails = returnBooleanCheckedStatus(this.exportreportCWEID) + ";" + returnBooleanCheckedStatus(this.exportreportWASCID) + ";" + returnBooleanCheckedStatus(this.exportreportDescription) + ";" + returnBooleanCheckedStatus(this.exportreportOtherInfo) + ";" + returnBooleanCheckedStatus(this.exportreportSolution) + ";"
                            + returnBooleanCheckedStatus(this.exportreportReference) + ";" + returnBooleanCheckedStatus(this.exportreportRequestHeader) + ";" + returnBooleanCheckedStatus(this.exportreportResponseHeader) + ";" + returnBooleanCheckedStatus(this.exportreportRequestBody) + ";" + returnBooleanCheckedStatus(this.exportreportResponseBody) + ";";
                    buildSuccess = exportReport(listener, clientApi, workspace, this.selectedExportFormats, this.evaluatedReportFilename, sourceDetails, alertSeverity, alertDetails, buildSuccess);
                }
                else Utils.loggerMessage(listener, 1, "SKIP GENERATE REPORT(S)");

                /* CREATE JIRA ISSUES */
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] CREATE JIRA ISSUES [ {1} ]", Utils.ZAP, String.valueOf(this.jiraCreate).toUpperCase());
                if (this.jiraCreate) jiraCreate(listener, clientApi, this.jiraBaseURL, this.jiraUsername, this.jiraPassword, this.jiraProjectKey, this.jiraAssignee, this.jiraAlertHigh, this.jiraAlertMedium, this.jiraAlertLow, this.jiraFilterIssuesByResourceType);
                else Utils.loggerMessage(listener, 1, "SKIP CREATING JIRA ISSUES");

                /* PERSIST SESSION */
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] PERSIST SESSION [ {1} ]", Utils.ZAP, String.valueOf(!this.autoLoadSession).toUpperCase());
                if (!this.autoLoadSession) persistSession(listener, clientApi, workspace, this.sessionFilename);
                else Utils.loggerMessage(listener, 1, "SKIP PERSISTINT A SESSION BECAUSE ONE WAS ALREADY LOADED.");

                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] SUMMARY...", Utils.ZAP);
                String numberOfAlerts = ((ApiResponseElement) clientApi.core.numberOfAlerts("")).getValue();
                Utils.loggerMessage(listener, 1, "ALERTS COUNT [ {1} ]", Utils.ZAP, numberOfAlerts);
                String numberOfMessages = ((ApiResponseElement) clientApi.core.numberOfMessages("")).getValue();
                Utils.loggerMessage(listener, 1, "MESSAGES COUNT [ {1} ]", Utils.ZAP, numberOfMessages);
            }
        }
        catch (Exception e) {
            listener.error(ExceptionUtils.getStackTrace(e));
            buildSuccess = false;
        }
        finally {
            try {
                stopZAP(listener, clientApi);
            }
            catch (ClientApiException e) {
                listener.error(ExceptionUtils.getStackTrace(e));
                buildSuccess = false;
            }
        }

        // Utils.loggerMessage(listener, 0, "[{0}] LOG SEARCH...", Utils.ZAP);
        // // No workspace before the first build, so workspace is null
        // if (workspace != null) {
        // File[] listFiles = {};
        // try {
        // listFiles = workspace.act(new LogCallable(this.evaluatedZapSettingsDir));
        // }
        // catch (IOException e) {
        // // No listener because it's not during a build but it's on the job config page
        // e.printStackTrace();
        // }
        // catch (InterruptedException e) {
        // // No listener because it's not during a build but it's on the job config page
        // e.printStackTrace();
        // }
        // for (File listFile : listFiles) {
        // Utils.loggerMessage(listener, 1, "[ {0} ] LOG HAS BEEN FOUND", FilenameUtils.getBaseName(listFile.getName()));
        // }
        // }
        Utils.lineBreak(listener);
        return buildSuccess;
    }

    /**
     * method used to return the checked state inside CREATE JIRA ISSUES
     **/
    private String returnCheckedStatus(boolean checkedStatus) { return checkedStatus ? "1" : "0"; }

    /**
     * method used to return the checked state inside CREATE JIRA ISSUES
     **/
    private String returnBooleanCheckedStatus(boolean checkedStatus) { return checkedStatus ? "t" : "f"; }

    /**
     * Converts the ZAP API status response to an integer
     *
     * @param response
     *            the ZAP API response code
     * @return the integer status of the ApiResponse
     */
    private int statusToInt(final ApiResponse response) { return Integer.parseInt(((ApiResponseElement) response).getValue()); }

    /**
     * Converts the ZAP API status response to an String
     *
     * @param response
     *            the ZAP API response code
     * @return the String status of the ApiResponse
     */
    private String statusToString(final ApiResponse response) { return ((ApiResponseElement) response).getValue(); }

    /**
     * get user id
     *
     * @param response
     *            the ZAP API response code
     * @return the user ID of the user
     */
    private String extractUserId(ApiResponse response) { return ((ApiResponseElement) response).getValue(); }

    /**
     * get context id
     *
     * @param response
     *            the ZAP API response code
     * @return the context ID of the context
     */
    private String extractContextId(ApiResponse response) { return ((ApiResponseElement) response).getValue(); }

    /**
     * set up a context and add/exclude url to/from it
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param URL
     *            the URL to be added to context
     * @param excludedURL
     *            the URL to exclude from context
     * @param clientApi
     *            the client API to use ZAP API methods
     * @return the context ID of the context
     * @throws ClientApiException
     */
    private String setUpContext(BuildListener listener, ClientApi clientApi, String contextName, String includedURL, String excludedURL) throws ClientApiException {
        String contextIdTemp;
        includedURL = includedURL.trim();
        excludedURL = excludedURL.trim();

        Utils.loggerMessage(listener, 0, "[{0}] CREATE NEW CONTEXT [ {1} ]", Utils.ZAP, contextName);
        Utils.lineBreak(listener);
        /**
         * @class org.zaproxy.clientapi.gen.Context
         * @method newContext
         * @param String apikey
         * @param String contextname
         * @throws ClientApiException
         */
        contextIdTemp = extractContextId(clientApi.context.newContext(API_KEY, contextName));

        /* INCLUDE URL(S) IN CONTEXT */
        Utils.loggerMessage(listener, 0, "[{0}] INCLUDE IN CONTEXT", Utils.ZAP);
        if (!includedURL.equals("")) try {
            String[] urls = includedURL.split("\n");
            String contextIncludedURL = "";

            for (int i = 0; i < urls.length; i++) {
                urls[i] = urls[i].trim();
                if (!urls[i].isEmpty()) {
                    contextIncludedURL = urls[i];
                    /**
                     * @class org.zaproxy.clientapi.gen.Context
                     * @method includeInContext
                     * @param String apikey
                     * @param String contextname
                     * @param String regex
                     * @throws ClientApiException
                     */
                    clientApi.context.includeInContext(API_KEY, contextName, contextIncludedURL);
                    Utils.loggerMessage(listener, 1, "[ {0} ]", contextIncludedURL);
                }

            }
        }
        catch (ClientApiException e) {
            e.printStackTrace();
            listener.error(ExceptionUtils.getStackTrace(e));
        }
        Utils.lineBreak(listener);

        /* EXCLUDE URL(S) FROM CONTEXT */
        Utils.loggerMessage(listener, 0, "[{0}] EXCLUDE FROM CONTEXT", Utils.ZAP);
        if (!excludedURL.equals("")) try {
            String[] urls = excludedURL.split("\n");
            String contextExcludedURL = "";

            for (int i = 0; i < urls.length; i++) {
                urls[i] = urls[i].trim();
                if (!urls[i].isEmpty()) {
                    contextExcludedURL = urls[i];
                    /**
                     * @class org.zaproxy.clientapi.gen.Context
                     * @method excludeFromContext
                     * @param String apikey
                     * @param String contextname
                     * @param String regex
                     * @throws ClientApiException
                     */
                    clientApi.context.excludeFromContext(API_KEY, contextName, contextExcludedURL);
                    Utils.loggerMessage(listener, 1, "[ {0} ]", contextExcludedURL);
                }

            }
        }
        catch (ClientApiException e) {
            e.printStackTrace();
            listener.error(ExceptionUtils.getStackTrace(e));
        }
        return contextIdTemp;
    }

    /**
     * set up form based authentication method for the created context
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param contextId
     *            id of the creted context
     * @param loginURL
     *            login page url
     * @param loggedInIdicator
     *            indication for know its logged in
     * @param extraPostData
     *            other post data than credentials
     * @param usernameParameter
     *            parameter define in passing username
     * @param passwordParameter
     *            parameter that define in passing password for the user
     * @throws ClientApiException
     * @throws UnsupportedEncodingException
     */
    private void setUpFormBasedAuth(BuildListener listener, ClientApi clientApi, String contextId, String loginURL, String loggedInIndicator, String extraPostData, String usernameParameter, String passwordParameter) throws ClientApiException, UnsupportedEncodingException {

        String loginRequestData = usernameParameter + "={%username%}&" + passwordParameter + "={%password%}";
        if (extraPostData.length() > 0) loginRequestData = loginRequestData + "&" + extraPostData;

        // set form based authentication method
        // Prepare the configuration in a format similar to how URL parameters
        // are formed. This
        // means that any value we add for the configuration values has to be
        // URL encoded.
        StringBuilder formBasedConfig = new StringBuilder();
        formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginURL, "UTF-8"));
        formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));
        // {"methodConfigParams":[{"name":"loginUrl","mandatory":"true"},{"name":"loginRequestData","mandatory":"false"}]}

        /*
         * @class org.zaproxy.clientapi.gen.Authentication
         *
         * @method setAuthenticationMethod
         *
         * @param String String apikey
         *
         * @param String contextid
         *
         * @param String authmethodname (formBasedAuthentication, scriptBasedAuthentication, httpAuthentication and manualAuthentication)
         *
         * @param String authmethodconfigparams
         *
         * @throws ClientApiException
         *
         * @see https://github.com/zaproxy/zap-api-java/blob/master/subprojects/zap-clientapi/src/examples/java/org/zaproxy/clientapi/examples/authentication/FormBasedAuthentication.java
         *
         * @see https://github.com/zaproxy/zaproxy/wiki/FAQformauth which mentions the ZAP API (but the above example is probably more useful)
         */
        Utils.loggerMessage(listener, 0, "[{0}] FORM BASED AUTH SET AS: {1}", Utils.ZAP, formBasedConfig.toString());
        Utils.lineBreak(listener);
        clientApi.authentication.setAuthenticationMethod(API_KEY, contextId, "formBasedAuthentication", formBasedConfig.toString());

        Utils.loggerMessage(listener, 0, "[{0}] AUTH CONFIG:", Utils.ZAP);
        ApiResponseSet authData = (ApiResponseSet) clientApi.authentication.getAuthenticationMethod(contextId);
        List<String> authList = new ArrayList<String>(Arrays.asList(authData.toString(0).replace("\t", "").split("\\r?\\n")));
        authList.remove(0);
        authList.remove(authList.size() - 1);

        for (String tmp : authList)
            Utils.loggerMessage(listener, 1, "{0}", tmp);

        Utils.loggerMessage(listener, 1, "loggedInIndicator = {0}", loggedInIndicator);
        // add logged in indicator
        if (!loggedInIndicator.equals("")) clientApi.authentication.setLoggedInIndicator(API_KEY, contextId, loggedInIndicator);
        Utils.lineBreak(listener);
    }

    /**
     * set up script based authentication method for the created context
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the ZAP API client
     * @param contextId
     * @param loginURL
     * @param loggedInIndicator
     *            the indication that the user is logged in
     * @param extraPostData
     * @param scriptName
     *            the name of the authentication script used to authenticate the user
     * @param protectedPages
     * @throws UnsupportedEncodingException
     * @throws ClientApiException
     */
    private void setUpScriptBasedAuth(BuildListener listener, ClientApi clientApi, ArrayList<ZAPAuthScriptParam> authScriptParams, String contextId, String loginURL, String loggedInIndicator, String extraPostData, String scriptName, String protectedPages) throws UnsupportedEncodingException, ClientApiException {

        // set script based authentication method
        // Prepare the configuration in a format similar to how URL parameters
        // are formed. This
        // means that any value we add for the configuration values has to be
        // URL encoded.
        StringBuilder scriptBasedConfig = new StringBuilder();
        scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
        if (!authScriptParams.isEmpty()) addZAPAuthScriptParam(authScriptParams, scriptBasedConfig);

        // StringBuilder scriptBasedConfig = new StringBuilder();
        // scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
        // scriptBasedConfig.append("&loginUrl=").append(URLEncoder.encode(loginURL, "UTF-8"));
        // scriptBasedConfig.append("&protectedPages=").append(URLEncoder.encode(protectedPages, "UTF-8"));
        // scriptBasedConfig.append("&extraPostData=").append(URLEncoder.encode(extraPostData, "UTF-8"));
        // {"methodConfigParams":[{"name":"scriptName","mandatory":"true"},{"name":"scriptConfigParams","mandatory":"false"}]}

        Utils.loggerMessage(listener, 0, "[{0}] SCRIPT BASED AUTH SET AS: {1}", Utils.ZAP, scriptBasedConfig.toString());
        Utils.lineBreak(listener);

        // TODO ASK ZAP DEV TEAM
        // ApiResponse
        // org.zaproxy.clientapi.gen.Authentication.setAuthenticationMethod(String
        // apikey, String contextid, String authmethodname, String
        // authmethodconfigparams) throws ClientApiException
        // it's possible to know more of authmethodconfigparams for each authentication method with http://localhost:8080/JSON/authentication/view/getAuthenticationMethodConfigParams/?authMethodName=scriptBasedAuthentication
        Utils.loggerMessage(listener, 0, "[{0}] LOAD SCRIPT FOR AUTHENTICATION", Utils.ZAP);
        clientApi.authentication.setAuthenticationMethod(API_KEY, contextId, "scriptBasedAuthentication", scriptBasedConfig.toString());

        /*
         * 2:14:01 PM - thc202: and optional 2:14:56 PM - thc202: that value is the Utils.indentation level when generating the string representation of the API response 2:14:57 PM - thc202: https://github.com/zaproxy/zap-api-java/blob/master/subprojects/zap-clientapi/src/main/java/org/zaproxy/clientapi/core/ApiResponseSet.java#L61
         */

        // https://github.com/zaproxy/zap-api-java/blob/master/subprojects/zap-clientapi/src/main/java/org/zaproxy/clientapi/core/ApiResponseSet.java#L61

        // no, the string (if outputted) would be shifted to the right one more level
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 0, "[{0}] AUTH CONFIG:", Utils.ZAP);
        ApiResponseSet authData = (ApiResponseSet) clientApi.authentication.getAuthenticationMethod(contextId);
        List<String> authList = new ArrayList<String>(Arrays.asList(authData.toString(0).replace("\t", "").split("\\r?\\n")));
        authList.remove(0);
        authList.remove(authList.size() - 1);

        for (String tmp : authList)
            Utils.loggerMessage(listener, 1, "{0}", tmp);

        Utils.loggerMessage(listener, 1, "loggedInIndicator = {0}", loggedInIndicator);
        // add logged in indicator
        if (!loggedInIndicator.equals("")) clientApi.authentication.setLoggedInIndicator(API_KEY, contextId, loggedInIndicator);
        Utils.lineBreak(listener);
    }

    /**
     * set up user for the context and enable user
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param username
     *            user name to be used in authentication
     * @param password
     *            password for the authentication user
     * @param contextId
     *            id of the created context
     * @return userId id of the newly setup user
     * @throws ClientApiException
     * @throws UnsupportedEncodingException
     */
    private String setUpUser(BuildListener listener, ClientApi clientApi, String contextId, String username, String password) throws ClientApiException, UnsupportedEncodingException {

        String userIdTemp;
        /**
         * Create a new user name and add it to the context specified by the id, at least one user is required in order to extract the id
         *
         * @class org.zaproxy.clientapi.gen.Users
         * @method newUser
         * @param String apikey
         * @param String contextid
         * @param String name
         * @throws ClientApiException
         */
        userIdTemp = extractUserId(clientApi.users.newUser(API_KEY, contextId, username));

        /* The created user has key-value pair association (Session Properties > Context > Context Name > Users), not to be confused with Authentication but it is dependent on it.
         *     form-based is hard coded in the api to lower case
         *     script-based (zest) is hard coded to be Camel case
         *     script-based (java script) is user defined, so force it to be Camel case to match zest
         */
        String tempUsernameParam = "username";
        String tempPasswordParam = "password";
        if (authMethod.equals(SCRIPT_BASED)) {
            tempUsernameParam = "Username";
            tempPasswordParam = "Password";
        }

        /* Prepare the authentication configuration just like you would the query string (name/value pairs) for a URL GET request, remember to URL encode */
        StringBuilder userAuthConfig = new StringBuilder();
        userAuthConfig.append(tempUsernameParam).append("=").append(URLEncoder.encode(username, "UTF-8")).append("&").append(tempPasswordParam).append("=").append(URLEncoder.encode(password, "UTF-8"));

        Utils.loggerMessage(listener, 0, "[{0}] USER CREATION", Utils.ZAP);
        /**
         * @class org.zaproxy.clientapi.gen.Users
         * @method setAuthenticationCredentials
         * @param String apikey
         * @param String contextid
         * @param String String userid
         * @param String String authcredentialsconfigparams
         * @throws ClientApiException
         */
        clientApi.users.setAuthenticationCredentials(API_KEY, contextId, userIdTemp, userAuthConfig.toString());

        Utils.loggerMessage(listener, 1, "NEW USER ADDED [ SUCCESSFULLY ]", tempUsernameParam, username);
        Utils.loggerMessage(listener, 2, "{0}: {1}", tempUsernameParam, username);
        Utils.loggerMessage(listener, 2, "{0}: ****", tempPasswordParam);

        /**
         * @class org.zaproxy.clientapi.gen.Users
         * @method setUserEnabled
         * @param String apikey
         * @param String contextid
         * @param String String userid
         * @param String String enabled
         * @throws ClientApiException
         */
        clientApi.users.setUserEnabled(API_KEY, contextId, userIdTemp, "true");
        Utils.loggerMessage(listener, 1, "USER {0} IS NOW ENABLED", username);

        /* Forces Authenticated User during SPIDER SCAN and AJAX SPIDER */
        setUpForcedUser(listener, clientApi, contextId, userIdTemp);

        return userIdTemp;
    }

    /**
     * set up forced user for the context and enable user, this help to make spidering and ajax spidering as authenticated user
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param contextId
     *            id of the created context
     * @return userId id of the newly setup user
     * @throws ClientApiException
     * @throws UnsupportedEncodingException
     */
    private void setUpForcedUser(BuildListener listener, ClientApi clientApi, String contextid, String userid) throws ClientApiException, UnsupportedEncodingException {
        /**
         * @class org.zaproxy.clientapi.gen.ForcedUser
         * @method setForcedUser
         * @param String apikey
         * @param String contextid
         * @param String userid
         * @throws ClientApiException
         */
        clientApi.forcedUser.setForcedUser(API_KEY, contextid, userid);

        /**
         * @class org.zaproxy.clientapi.gen.ForcedUser
         * @method setForcedUserModeEnabled
         * @param String apikey
         * @param boolean bool
         * @throws ClientApiException
         */
        clientApi.forcedUser.setForcedUserModeEnabled(API_KEY, true);
    }

    /**
     * Set up all authentication details
     *
     * @param loginURL
     *            login page url
     * @param username
     *            user name to be used in authentication
     * @param password
     *            password for the authentication user
     * @param loggedInIndicator
     *            indication for know its logged in
     * @param extraPostData
     *            other post data than credentials
     * @param authMethod
     * @param usernameParameter
     *            parameter define in passing username
     * @param passwordParameter
     *            parameter that define in passing password for the user
     * @param scriptName
     * @param protectedPages
     * @throws ClientApiException
     * @throws InterruptedException
     * @throws UnsupportedEncodingException
     */
    private String setUpAuthentication(BuildListener listener, ClientApi clientApi, String contextId, String loginURL, String username, String password, String loggedInIndicator, String extraPostData, String authMethod, String usernameParameter, String passwordParameter, String scriptName, ArrayList<ZAPAuthScriptParam> authScriptParams) throws ClientApiException, UnsupportedEncodingException {
        if (authMethod.equals(FORM_BASED)) setUpFormBasedAuth(listener, clientApi, contextId, loginURL, loggedInIndicator, extraPostData, usernameParameter, passwordParameter);
        else if (authMethod.equals(SCRIPT_BASED)) setUpScriptBasedAuth(listener, clientApi, authScriptParams, contextId, loginURL, loggedInIndicator, extraPostData, scriptName, protectedPages);

        return setUpUser(listener, clientApi, contextId, username, password);
    }

    /**
     * Search for all links and pages on the URL and raised passives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param url
     *            the url to investigate
     *
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void spiderScanURL(BuildListener listener, ClientApi clientApi, boolean run, String targetURL, final String contextName, final String contextId, final String userId, boolean authMode, boolean recurse, boolean subtreeOnly, int maxChildrenToCrawl) throws ClientApiException, InterruptedException {
        if (run) {
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 1, "SPIDER SCAN SETTINGS", Utils.ZAP);
            Utils.loggerMessage(listener, 2, "AUTHENTICATED SPIDER SCAN [ {0} ]", String.valueOf(authMode).toUpperCase());
            Utils.loggerMessage(listener, 2, "RECURSE: [ {0} ]", String.valueOf(recurse).toUpperCase());
            Utils.loggerMessage(listener, 2, "SUB TREE ONLY: [ {0} ]", String.valueOf(subtreeOnly).toUpperCase());
            Utils.loggerMessage(listener, 2, "MAX CHILDREN: [ {0} ]", String.valueOf(maxChildrenToCrawl));
            if (!authMode) {
                Utils.loggerMessage(listener, 2, "CONTEXT NAME: [ {0} ]", contextName);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] SPIDER SCAN THE SITE [ {1} ]", Utils.ZAP, targetURL);
                Utils.lineBreak(listener);
                /*
                 * @class org.zaproxy.clientapi.gen.Spider
                 *
                 * @method scan
                 *
                 * @param String apikey
                 * @param String url the starting point/seed of the spider (might be null or empty if the context already has a URL to start)
                 * @param String maxchildren a number (0 default is no maximum) or empty string
                 * @param String recurse true/false or empty string, default is true
                 * @param String contextname the name of the context (if empty string, it's not spidering a context)
                 * @param String true/false or subtreeonly empty string (default is false, which is to not limit to a subtree)
                 *
                 * @throws ClientApiException
                 */
                clientApi.spider.scan(API_KEY, targetURL, String.valueOf(maxChildrenToCrawl), String.valueOf(recurse), contextName, String.valueOf(subtreeOnly));
            }
            else if (authMode) {
                Utils.loggerMessage(listener, 2, "CONTEXT ID: [ {0} ]", contextId);
                Utils.loggerMessage(listener, 2, "USER ID: [ {0} ]", userId);
                ApiResponseSet userData = (ApiResponseSet) clientApi.users.getUserById(contextId, userId);
                String name = userData.getAttribute("name");
                Utils.loggerMessage(listener, 2, "USER NAME: [ {0} ]", name);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] SPIDER SCAN THE SITE [ {1} ] AS USER [ {2} ]", Utils.ZAP, targetURL, name);
                Utils.lineBreak(listener);
                /*
                 * @class org.zaproxy.clientapi.gen.Spider
                 *
                 * @method scanAsUser
                 *
                 * @param String String apikey
                 * @param String contextid the id of the context (if empty string, it's not spidering a context)
                 * @param String userid
                 * @param String url the starting point/seed of the spider (might be null or empty if the context already has a URL to start)
                 * @param String maxchildren a number (0 default is no maximum) or empty string
                 * @param String recurse true/false or empty string, default is true
                 * @param String subtreeonly true/false or subtreeonly empty string (default is false, which is to not limit to a subtree)
                 *
                 * @throws ClientApiException
                 */
                clientApi.spider.scanAsUser(API_KEY, contextId, userId, targetURL, String.valueOf(maxChildrenToCrawl), String.valueOf(recurse), String.valueOf(subtreeOnly));
            }

            /**
             * Wait for completed SPIDER SCAN (equal to 100)
             *
             * @class org.zaproxy.clientapi.gen.Spider
             *
             * @method status
             *
             * @param String scanid Empty string returns the status of the most recent scan
             *
             * @throws ClientApiException
             */
            while (statusToInt(clientApi.spider.status("")) < 100) {
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] SPIDER SCAN STATUS [ {1}% ]", Utils.ZAP, String.valueOf(statusToInt(clientApi.spider.status(""))));
                /**
                 * @class org.zaproxy.clientapi.gen.Core
                 *
                 * @method numberOfAlerts
                 *
                 * @param String baseurl Empty String returns the number of alerts for the most recent scan
                 *
                 * @throws ClientApiException
                 */
                String numberOfAlerts = ((ApiResponseElement) clientApi.core.numberOfAlerts("")).getValue();
                Utils.loggerMessage(listener, 0, "[{0}] ALERTS COUNT [ {1} ]", Utils.ZAP, numberOfAlerts);
                Utils.lineBreak(listener);
                Thread.sleep(TREAD_SLEEP);
            }
        }
        else Utils.loggerMessage(listener, 1, "SKIP SPIDER SCAN FOR THE SITE [ {0} ]", targetURL);
    }

    /**
     * Search for all links and pages on the URL and raised passives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param url
     *            the url to investigate
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void ajaxSpiderURL(BuildListener listener, ClientApi clientApi, boolean run, String targetURL, boolean inScopeOnly) throws ClientApiException, InterruptedException {
        if (run) {
            Utils.loggerMessage(listener, 1, "AJAX SPIDER SETTINGS", Utils.ZAP);
            Utils.loggerMessage(listener, 2, "SUB TREE ONLY: [ {0} ]", String.valueOf(inScopeOnly).toUpperCase());
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] AJAX SPIDER THE SITE [ {1} ]", Utils.ZAP, targetURL);
            Utils.lineBreak(listener);

            /**
             * @class org.zaproxy.clientapi.gen.AjaxSpider
             *
             * @method scan
             *
             * @param String apikey
             * @param String url
             * @param String inscope
             *
             * @throws ClientApiException
             */
            clientApi.ajaxSpider.scan(API_KEY, targetURL, String.valueOf(inScopeOnly));

            /**
             * Wait for completed AJAX SPIDER (not equal to 'running')
             *
             * @class org.zaproxy.clientapi.gen.AjaxSpider
             *
             * @method status
             *
             * @throws ClientApiException
             */
            while ("running".equalsIgnoreCase(statusToString(clientApi.ajaxSpider.status()))) {
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] AJAX SPIDER STATUS [ {1} ]", Utils.ZAP, statusToString(clientApi.ajaxSpider.status()));
                /**
                 * @class org.zaproxy.clientapi.gen.Core
                 *
                 * @method numberOfAlerts
                 *
                 * @param String baseurl Empty String returns the number of alerts for the most recent scan
                 *
                 * @throws ClientApiException
                 */
                String numberOfAlerts = ((ApiResponseElement) clientApi.core.numberOfAlerts("")).getValue();
                Utils.loggerMessage(listener, 0, "[{0}] ALERTS COUNT [ {1} ]", Utils.ZAP, numberOfAlerts);
                Utils.lineBreak(listener);
                Thread.sleep(TREAD_SLEEP);
            }
        }
        else Utils.loggerMessage(listener, 1, "SKIP AXAJ SPIDER FOR THE SITE [ {0} ]", targetURL);
    }

    /**
     * Scan all pages found at url and raised actives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param targetURL
     *            the url to scan
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void activeScanURL(BuildListener listener, ClientApi clientApi, boolean run, String targetURL, final String contextId, final String userId, boolean authMode, String policy, boolean recurse) throws ClientApiException, InterruptedException {
        if (run) {
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 1, "ACTIVE SCAN SETTINGS", Utils.ZAP);
            Utils.loggerMessage(listener, 2, "AUTHENTICATED ACTIVE SCAN [ {0} ]", String.valueOf(authMode).toUpperCase());
            if (activeScanPolicy == null || activeScanPolicy.isEmpty()) Utils.loggerMessage(listener, 2, "POLICY: [ Default policy ]");
            else Utils.loggerMessage(listener, 2, "POLICY: [ {0} ]", policy);
            Utils.loggerMessage(listener, 2, "RECURSE: [ {0} ]", String.valueOf(recurse).toUpperCase());

            if (!authMode) {
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] ACTIVE SCAN THE SITE [ {1} ]", Utils.ZAP, targetURL);
                Utils.lineBreak(listener);

                /**
                 * @class org.zaproxy.clientapi.gen.Ascan
                 *
                 * @method scan
                 *
                 * @param String String apikey
                 * @param String url
                 * @param String recurse true/false, default is true
                 * @param String inscopeonly true/false, default is false, do not allow user change
                 * @param String scanpolicyname depends on the policies that ZAP has, activeScanPolicy, uses default if empty or null
                 * @param String method can be any method GET/POST/PUT/DELETE..., default is null
                 * @param String postdata the POST data a=b&c=d (or whatever format is used), default is null
                 *
                 * @throws ClientApiException
                 *
                 * @notes all of them can be null or empty strings, which is the same as not using them
                 *
                 * @default values: true, false, default policy, GET, nothing
                 */
                clientApi.ascan.scan(API_KEY, targetURL, String.valueOf(recurse), "false", policy, null, null);
            }
            else if (authMode) {
                Utils.loggerMessage(listener, 2, "CONTEXT ID: [ {0} ]", contextId);
                Utils.loggerMessage(listener, 2, "USER ID: [ {0} ]", userId);
                ApiResponseSet userData = (ApiResponseSet) clientApi.users.getUserById(contextId, userId);
                String name = userData.getAttribute("name");
                Utils.loggerMessage(listener, 2, "USER NAME: [ {0} ]", name);
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] ACTIVE SCAN THE SITE [ {1} ] AS USER [ {2} ]", Utils.ZAP, targetURL, name);
                Utils.lineBreak(listener);

                /**
                 * @class org.zaproxy.clientapi.gen.Ascan
                 *
                 * @method scanAsUser
                 *
                 * @param String apikey
                 * @param String url
                 * @param String contextid
                 * @param String userid Cannot be null
                 * @param String recurse
                 * @param String scanpolicyname
                 * @param String method
                 * @param String postdata
                 *
                 * @throws ClientApiException
                 */
                clientApi.ascan.scanAsUser(API_KEY, targetURL, contextId, userId, String.valueOf(recurse), policy, null, null);
            }

            /**
             * The status uses the ID of the scan which is returned when the scan is started, if nothing is set it returns the status of the last scan.
             *
             * Wait for completed ACTIVE SCAN (equal to 100)
             *
             * @class org.zaproxy.clientapi.gen.Spider
             *
             * @method status
             *
             * @param String scanid Empty string returns the status of the most recent scan
             *
             * @throws ClientApiException
             */
            while (statusToInt(clientApi.ascan.status("")) < 100) {
                Utils.lineBreak(listener);
                Utils.loggerMessage(listener, 0, "[{0}] ACTIVE SCAN STATUS [ {1}% ]", Utils.ZAP, String.valueOf(statusToInt(clientApi.ascan.status(""))));
                /**
                 * Allows to restrict by site/URL, if none is set it returns the number of all alerts.
                 *
                 * @class org.zaproxy.clientapi.gen.Core
                 *
                 * @method numberOfAlerts
                 *
                 * @param String baseurl Empty String returns the number of alerts for the most recent scan
                 *
                 * @throws ClientApiException
                 *
                 * @see http://localhost:8080/UI/core/view/numberOfAlerts/ For description
                 */
                String numberOfAlerts = ((ApiResponseElement) clientApi.core.numberOfAlerts("")).getValue();
                Utils.loggerMessage(listener, 0, "[{0}] ALERTS COUNT [ {1} ]", Utils.ZAP, numberOfAlerts);
                /**
                 * Allows to restrict by site/URL, if none is set it returns the number of all messages.
                 *
                 * @class org.zaproxy.clientapi.gen.Core
                 *
                 * @method numberOfMessages
                 *
                 * @param String baseurl
                 *
                 * @throws ClientApiException
                 */
                String numberOfMessages = ((ApiResponseElement) clientApi.core.numberOfMessages("")).getValue();
                Utils.loggerMessage(listener, 0, "[{0}] MESSAGES COUNT [ {1} ]", Utils.ZAP, numberOfMessages);
                Utils.lineBreak(listener);
                Thread.sleep(TREAD_SLEEP);
            }
        }
        else Utils.loggerMessage(listener, 1, "SKIP ACTIVE SCAN FOR THE SITE [ {0} ]", targetURL);
    }

    /**
     * Stop ZAproxy if it has been previously started.
     *
     * @param clientApi
     *            the client API to use ZAP API methods
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @throws ClientApiException
     */
    // private void stopZAP(ZAProxy zaproxy, ClientApi clientApi,
    // BuildListener listener) throws ClientApiException {
    private void stopZAP(BuildListener listener, ClientApi clientApi) throws ClientApiException {
        if (clientApi != null) {
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] SHUTDOWN [ START ]", Utils.ZAP);
            Utils.lineBreak(listener);
            // ApiResponse org.zaproxy.clientapi.gen.Core.shutdown(String apikey) throws ClientApiException
            clientApi.core.shutdown(API_KEY);
        }
        else Utils.loggerMessage(listener, 0, "[{0}] SHUTDOWN [ ERROR ]", Utils.ZAP);
    }

    /**
     * Descriptor for {@link ZAPDriver}. Used as a singleton. The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/com/github/jenkinsci/zaproxyplugin/ZAPDriver/*.jelly</tt> for the actual HTML fragment for the configuration screen.
     */
    @Extension
    public static class ZAPDriverDescriptorImpl extends Descriptor<ZAPDriver> implements Serializable {

        private static final long serialVersionUID = 4028279269334325901L;

        /**
         * To persist global configuration information, simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */

        /** Represents the build's workspace */
        private FilePath workspace;

        public void setWorkspace(FilePath ws) { this.workspace = ws; }

        @Override
        public String getDisplayName() { return null; }

        /**
         * Map where key is the report format represented by a String and value is a ZAPreport object allowing to generate a report with the corresponding format.
         */
        private Map<String, ZAPReport> mapFormatReport;

        public Map<String, ZAPReport> getMapFormatReport() { return mapFormatReport; }

        public List<String> getAllFormats() { return new ArrayList<String>(mapFormatReport.keySet()); }

        public List<String> getAllExportFormats() {
            ArrayList<String> arr = new ArrayList<String>();
            arr.add(EXPORT_REPORT_FORMAT_XML);
            arr.add(EXPORT_REPORT_FORMAT_XHTML);
            arr.add(EXPORT_REPORT_FORMAT_JSON);
            return arr;
        }
        /**
         * In order to load the persisted global configuration, you have to call load() in the constructor.
         */
        public ZAPDriverDescriptorImpl() {
            mapFormatReport = ZAPReportCollection.getInstance().getMapFormatReport();
            load();
        }

        /**
         * Performs on-the-fly validation of the form field 'reportFilename'.
         *
         * @param reportFilename
         *            This parameter receives the value that the user has typed.
         * @return Indicates the outcome of the validation. This is sent to the browser.
         *         <p>
         *         Note that returning {@link FormValidation#error(String)} does not prevent the form from being saved. It just means that a message will be displayed to the user.
         */
        public FormValidation doCheckReportFilename(@QueryParameter("reportFilename") final String reportFilename) {
            //cannot have validation method and clazz
            if (reportFilename == null || reportFilename.isEmpty()) return FormValidation.error("Field is required");
            if (!FilenameUtils.getExtension(reportFilename).isEmpty()) return FormValidation.warning("A file extension is not necessary.");
            return FormValidation.ok();
        }

        /**
         * Performs on-the-fly validation of the form field 'sessionFilename'.
         * <p>
         * If the user wants to save session whereas a session is already loaded, the relative path to the saved session must be different from the relative path to the loaded session.
         *
         * @param loadSession
         *            Parameter to compare with sessionFilename.
         * @param sessionFilename
         *            This parameter receives the value that the user has typed.
         * @return Indicates the outcome of the validation. This is sent to the browser.
         *         <p>
         *         Note that returning {@link FormValidation#error(String)} does not prevent the form from being saved. It just means that a message will be displayed to the user.
         */
        public FormValidation doCheckSessionFilename(@QueryParameter("sessionFilename") final String sessionFilename) {
            if (sessionFilename == null || sessionFilename.isEmpty()) return FormValidation.error("Field is required");
            if (!FilenameUtils.getExtension(sessionFilename).isEmpty()) return FormValidation.warning("A file extension is not necessary. A default file extension will be added (.session)");
            return FormValidation.ok();
        }

        @Deprecated
        public FormValidation doCheckSessionFilenameOld(@QueryParameter("loadSession") final String loadSession, @QueryParameter("sessionFilename") final String sessionFilename) {
            // Contains just the name of the session (without workspace path and extension)
            String cleanLoadSession = null;
            if (workspace != null) {
                cleanLoadSession = loadSession.replace(workspace.getRemote(), "") // Remove workspace path
                        .replaceFirst("\\\\", "") // Remove separator after workspace path if windows
                        .replaceFirst("/", ""); // Remove separator after workspace path if Unix

                if (!cleanLoadSession.isEmpty() && (sessionFilename.equals(cleanLoadSession) || sessionFilename.equals(cleanLoadSession.replace(FILE_SESSION_EXTENSION, "")))) return FormValidation.error("The saved session filename is the same of the loaded session filename.");
            }

            if (!loadSession.isEmpty()) return FormValidation.warning("A session is loaded, so it's not necessary to save session");
            if (!FilenameUtils.getExtension(sessionFilename).isEmpty()) return FormValidation.warning("A file extension is not necessary. A default file extension will be added (.session)");
            return FormValidation.ok();
        }

        public FormValidation doCheckLoadSession(@QueryParameter("loadSession") final String loadSession) {
            if (loadSession == null || loadSession.isEmpty()) return FormValidation.error("Field is required");
            return FormValidation.ok();
        }

        public FormValidation doCheckIncludedURL(@QueryParameter("includedURL") final String includedURL) {
            if (includedURL == null || includedURL.isEmpty()) return FormValidation.error("Field is required");
            return FormValidation.ok();
        }

        public FormValidation doCheckAuthScript(@QueryParameter("authScript") final String authScript) {
            if (authScript == null || authScript.isEmpty()) return FormValidation.error("Field is required");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportTitle(@QueryParameter("exportreportTitle") final String exportreportTitle) {
            if (exportreportTitle == null || exportreportTitle.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportTitle.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportBy(@QueryParameter("exportreportBy") final String exportreportBy) {
            if (exportreportBy == null || exportreportBy.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportBy.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportFor(@QueryParameter("exportreportFor") final String exportreportFor) {
            if (exportreportFor == null || exportreportFor.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportFor.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportScanDate(@QueryParameter("exportreportScanDate") final String exportreportScanDate) {
            if (exportreportScanDate == null || exportreportScanDate.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportScanDate.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportReportDate(@QueryParameter("exportreportReportDate") final String exportreportReportDate) {
            if (exportreportReportDate == null || exportreportReportDate.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportReportDate.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportScanVersion(@QueryParameter("exportreportScanVersion") final String exportreportScanVersion) {
            if (exportreportScanVersion == null || exportreportScanVersion.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportScanVersion.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportReportVersion(@QueryParameter("exportreportReportVersion") final String exportreportReportVersion) {
            if (exportreportReportVersion == null || exportreportReportVersion.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportReportVersion.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            return FormValidation.ok();
        }

        public FormValidation doCheckExportreportReportDescription(@QueryParameter("exportreportReportDescription") final String exportreportReportDescription) {
            if (exportreportReportDescription == null || exportreportReportDescription.isEmpty()) return FormValidation.error("Field is required");
            if (exportreportReportDescription.contains(";")) return FormValidation.error("Field cannot contain the character ';'");
            if (exportreportReportDescription.contains("\n")) return FormValidation.error("Field cannot contain line breaks");
            return FormValidation.ok();
        }

        /**
         * List model to choose the alert report format
         *
         * @return a {@link ListBoxModel}
         */
        public ListBoxModel doFillSelectedReportFormatsItems() {
            ListBoxModel items = new ListBoxModel();
            for (String format : mapFormatReport.keySet())
                items.add(format);
            return items;
        }

        /**
         * List model to choose the export report format
         *
         * @return a {@link ListBoxModel}
         */
        public ListBoxModel doFillSelectedExportFormatsItems() {
            ListBoxModel items = new ListBoxModel();
            for (String item: getAllExportFormats())
                items.add(item);
            return items;
        }
        /**
         * List model to choose the tool used (normally, it should be the ZAProxy tool).
         *
         * @return a {@link ListBoxModel}
         */
        public ListBoxModel doFillToolUsedItems() {
            ListBoxModel items = new ListBoxModel();
            for (ToolDescriptor<?> desc : ToolInstallation.all())
                for (ToolInstallation tool : desc.getInstallations())
                    items.add(tool.getName());
            return items;
        }

        /**
         * List model to choose the policy file to use by ZAProxy scan. It's called on the remote machine (if present) to load all policy files in the ZAP default dir of the build's machine.
         *
         * @param zapSettingsDir
         *            A string that represents an absolute path to the directory that ZAP uses.
         * @return a {@link ListBoxModel}. It can be empty if zapSettingsDir doesn't contain any policy file.
         */
        public ListBoxModel doFillActiveScanPolicyItems(@QueryParameter String zapSettingsDir) {
            ListBoxModel items = new ListBoxModel();

            // No workspace before the first build, so workspace is null
            if (workspace != null) {
                File[] listFiles = {};
                try {
                    listFiles = workspace.act(new PolicyFileCallable(zapSettingsDir));
                }
                catch (IOException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                catch (InterruptedException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }

                items.add(""); // To not load a policy file, add a blank choice

                // Add policy files to the list, without their extension
                for (File listFile : listFiles)
                    items.add(FilenameUtils.getBaseName(listFile.getName()));
            }
            return items;
        }

        /**
         * List model to choose the authentication script file to use by ZAProxy scan. It's called on the remote machine (if present) to load all authentication script files in the ZAP default dir of the build's machine. The jenkins job must be started once in order to create the workspace, so this method can load the list of authentication scripts the authentication scripts must be stored in this directory : <zapSettingsDir>/scripts/authentication
         *
         * @param zapSettingsDir
         *            A string that represents an absolute path to the directory that ZAP uses.
         * @return a {@link ListBoxModel}. It can be empty if zapSettingsDir doesn't contain any policy file.
         */
        public ListBoxModel doFillAuthScriptItems(@QueryParameter String zapSettingsDir) {
            ListBoxModel items = new ListBoxModel();

            // No workspace before the first build, so workspace is null
            if (workspace != null) {
                File[] listFiles = {};
                try {
                    listFiles = workspace.act(new AuthScriptCallable(zapSettingsDir));
                }
                catch (IOException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                catch (InterruptedException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }

                items.add(""); // To not load a policy file, add a blank choice

                // Add script authentication files to the list, with their extension
                for (File listFile : listFiles)
                    items.add(FilenameUtils.getBaseName(listFile.getName()));
                //getName()
            }
            return items;
        }

        /**
         * List model to choose the ZAP session to use. It's called on the remote machine (if present) to load all session files in the build's workspace.
         *
         * @return a {@link ListBoxModel}. It can be empty if the workspace doesn't contain any ZAP sessions.
         * @throws InterruptedException
         * @throws IOException
         */
        public ListBoxModel doFillLoadSessionItems() throws IOException, InterruptedException {
            ListBoxModel items = new ListBoxModel();

            // No workspace before the first build, so workspace is null
            if (workspace != null) {
                Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {

                    private static final long serialVersionUID = 1328740269013881941L;

                    @Override
                    public Collection<String> invoke(File f, VirtualChannel channel) {

                        // List all files with FILE_SESSION_EXTENSION on the
                        // machine where the workspace is located
                        Collection<File> colFiles = FileUtils.listFiles(f, FileFilterUtils.suffixFileFilter(FILE_SESSION_EXTENSION), TrueFileFilter.INSTANCE);

                        Collection<String> colString = new ArrayList<String>();

                        // "Transform" File into String
                        for (File file : colFiles)
                            colString.add(file.getAbsolutePath());
                        // The following line is to remove the full path to
                        // the workspace,
                        // keep just the relative path to the session
                        // colString.add(file.getAbsolutePath().replace(workspace.getRemote()
                        // + File.separatorChar, ""));
                        return colString;
                    }

                    @Override
                    public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
                });

                items.add(""); // To not load a session, add a blank choice

                for (String s : sessionsInString)
                    items.add(s);
            }

            return items;
        }
    }

    /**
     * This class allows to search all ZAP policy files in the ZAP default dir of the remote machine (or local machine if there is no remote machine). It's used in the plugin configuration page to fill the list of policy files and choose one of them.
     */
    private static class PolicyFileCallable implements FileCallable<File[]> {

        private static final long serialVersionUID = 1328740269013881941L;

        private String zapSettingsDir;

        public PolicyFileCallable(String zapSettingsDir) { this.zapSettingsDir = zapSettingsDir; }

        @Override
        public File[] invoke(File f, VirtualChannel channel) {
            File[] listFiles = {};

            Path pathPolicyDir = Paths.get(zapSettingsDir, NAME_POLICIES_DIR_ZAP);

            if (Files.isDirectory(pathPolicyDir)) {
                File zapPolicyDir = new File(zapSettingsDir, NAME_POLICIES_DIR_ZAP);
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
                            if (str.equals(FILE_POLICY_EXTENSION)) return true;
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
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }

    /**
     * This class allows to search all ZAP authentication script files in the ZAP default dir of the remote machine (or local machine if there is no remote machine). It's used in the plugin configuration page to fill the list of authentication script files and choose one of them.
     */
    private static class AuthScriptCallable implements FileCallable<File[]> {

        private static final long serialVersionUID = 1328740269013881941L;

        private String zapSettingsDir;

        public AuthScriptCallable(String zapSettingsDir) { this.zapSettingsDir = zapSettingsDir; }

        @Override
        public File[] invoke(File f, VirtualChannel channel) {
            File[] listFiles = {};

            Path pathAuthScriptsDir = Paths.get(zapSettingsDir, NAME_SCRIPTS_DIR_ZAP, NAME_AUTH_SCRIPTS_DIR_ZAP);

            if (Files.isDirectory(pathAuthScriptsDir)) {
                File zapAuthScriptsDir = pathAuthScriptsDir.toFile();
                // create new filename filter (the filter returns true as all the extensions are accepted)
                FilenameFilter scriptFilter = new FilenameFilter() {

                    @Override
                    public boolean accept(File dir, String name) {
                        if (name.lastIndexOf('.') > 0) {
                            // get last index for '.' char
                            int lastIndex = name.lastIndexOf('.');

                            // get extension
                            String str = name.substring(lastIndex);

                            // match path name extension
                            if (str.equals(FILE_AUTH_SCRIPTS_JS_EXTENSION)) return true;
                            if (str.equals(FILE_AUTH_SCRIPTS_ZEST_EXTENSION)) return true;
                        }
                        return false;
                    }
                };

                // returns pathnames for files and directory
                listFiles = zapAuthScriptsDir.listFiles(scriptFilter);
            }
            return listFiles;
        }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }

    /**
     * This class allows to search all ZAP authentication script files in the ZAP default dir of the remote machine (or local machine if there is no remote machine). It's used in the plugin configuration page to fill the list of authentication script files and choose one of them.
     */
    private static class PluginCallable implements FileCallable<File[]> {

        private static final long serialVersionUID = 1328740269013881941L;

        private String zapSettingsDir;

        public PluginCallable(String zapSettingsDir) { this.zapSettingsDir = zapSettingsDir; }

        @Override
        public File[] invoke(File f, VirtualChannel channel) {
            File[] listFiles = {};

            Path pathAuthScriptsDir = Paths.get(zapSettingsDir, NAME_PLUGIN_DIR_ZAP);

            if (Files.isDirectory(pathAuthScriptsDir)) {
                File zapAuthScriptsDir = pathAuthScriptsDir.toFile();
                // create new filename filter (the filter returns true as all the extensions are accepted)
                FilenameFilter scriptFilter = new FilenameFilter() {

                    @Override
                    public boolean accept(File dir, String name) {
                        if (name.lastIndexOf('.') > 0) {
                            // get last index for '.' char
                            int lastIndex = name.lastIndexOf('.');

                            // get extension
                            String str = name.substring(lastIndex);

                            // match path name extension
                            if (str.equals(FILE_PLUGIN_EXTENSION)) return true;
                        }
                        return false;
                    }
                };

                // returns pathnames for files and directory
                listFiles = zapAuthScriptsDir.listFiles(scriptFilter);
            }
            return listFiles;
        }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }

    /**
     * This class allows to launch a method on a remote machine (if there is, otherwise, on a local machine). The method launched is to wait the complete initialization of ZAProxy.
     **/
    private static class WaitZAPDriverInitCallable implements FileCallable<Void> {

        private static final long serialVersionUID = -313398999885177679L;

        private BuildListener listener;
        private ZAPDriver zaproxy;

        public WaitZAPDriverInitCallable(BuildListener listener, ZAPDriver zaproxy) {
            this.listener = listener;
            this.zaproxy = zaproxy;
        }

        @Override
        public Void invoke(File f, VirtualChannel channel) {
            zaproxy.waitForSuccessfulConnectionToZap(listener, zaproxy.timeout);
            return null;
        }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }

    /*
     * Variable Declaration Getters allows to load members variables into UI. Setters
     */
    @Override
    public ZAPDriverDescriptorImpl getDescriptor() { return (ZAPDriverDescriptorImpl) super.getDescriptor(); }

    /* Overridden for better type safety. If your plugin doesn't really define any property on Descriptor, you don't have to do this. */
    private String availableFormatsString;
    private ArrayList<String> availableFormatsArray;

    private void getAvailableFormats(ZAPDriverDescriptorImpl zapDriver) {
        ArrayList<String> formats = new ArrayList<String>();
        StringBuilder sb = new StringBuilder();
        for (String format : zapDriver.getAllFormats())
            if (!formats.contains(format)) {
                formats.add(format);
                sb.append(".");
                sb.append(format);
                sb.append(", ");
            }
        for (String format : zapDriver.getAllExportFormats())
            if (!formats.contains(format)) {
                formats.add(format);
                sb.append(".");
                sb.append(format);
                sb.append(", ");
            }
        String extentions = sb.toString();
        if (extentions.contains(", ")) extentions = extentions.substring(0, extentions.length() - 2);
        this.availableFormatsString = extentions;
        this.availableFormatsArray = formats;
    }

    private String contextId; /* Id of the newly created context */

    private String userId; /* Id of the newly created user */

    private boolean startZAPFirst;

    public boolean getStartZAPFirst() { return startZAPFirst; }

    public void setStartZAPFirst(boolean startZAPFirst) { this.startZAPFirst = startZAPFirst; }

    private String zapHost; /* Host configured when ZAP is used as proxy */

    public String getZapHost() { return zapHost; }

    public void setZapHost(String zapHost) { this.zapHost = zapHost; }

    /** Host configured when ZAProxy is used as proxy (it's derived from the one above) */
    private String evaluatedZapHost;

    public String getEvaluatedZapHost() { return evaluatedZapHost; }

    public void setEvaluatedZapHost(String evaluatedZapHost) { this.evaluatedZapHost = evaluatedZapHost; }

    private String zapPort; /* Port configured when ZAP is used as proxy */

    public String getZapPort() { return zapPort; }

    public void setZapPort(String zapPort) { this.zapPort = zapPort; }

    /** Port configured when ZAProxy is used as proxy (it's derived from the one above) */
    private int evaluatedZapPort;

    public int getEvaluatedZapPort() { return evaluatedZapPort; }

    public void setEvaluatedZapPort(int evaluatedZapPort) { this.evaluatedZapPort = evaluatedZapPort; }

    private String zapProgram; /* Path to the ZAPJ program */

    private final ArrayList<ZAPCmdLine> cmdLinesZAP; /* List of all ZAP command lines specified by the user ArrayList because it needs to be Serializable (whereas List is not Serializable) */

    public List<ZAPCmdLine> getCmdLinesZAP() { return cmdLinesZAP; }

    private ArrayList<ZAPCmdLine> evaluatedCmdLinesZap;

    public List<ZAPCmdLine> getEvaluatedCmdLinesZap() { return evaluatedCmdLinesZap; }

    public void setEvaluatedCmdLinesZap(ArrayList<ZAPCmdLine> evaluatedCmdLinesZap) { this.evaluatedCmdLinesZap = evaluatedCmdLinesZap; }

    private final String jdk; /* The jdk to use to start ZAPJ */

    public String getJdk() { return jdk; }

    /* Gets the JDK that this Sonar builder is configured with, or null. */
    public JDK getJDK() { return Jenkins.getInstance().getJDK(jdk); }

    /*
     * True if automatically installed by Jenkins (ZAProxy is installed by Jenkins with a plugin like Custom Tools Plugin) False if already installed on the machine (ZAProxy is already installed)
     */

    private final String toolUsed; /* The ZAproxy tool to use */

    public String getToolUsed() { return toolUsed; }

    private final String zapHome; /* Environment variable about ZAPJ path */

    public String getZapHome() { return zapHome; }

    private final int timeout; /* Time total to wait for zap initialization. After this time, the program is stopped */

    public int getTimeout() { return timeout; }

    private final boolean autoInstall;

    public boolean getAutoInstall() { return autoInstall; }
    // --------------------------------------------------------------------------------------------------------------------------

    /* ZAP Settings */
    private final String zapSettingsDir; /* The default directory that ZAP uses */

    public String getZapSettingsDir() { return zapSettingsDir; }

    private String evaluatedZapSettingsDir;

    public String getEvaluatedZapSettingsDir() { return evaluatedZapSettingsDir; }

    public void setEvaluatedZapSettingsDir(String evaluatedZapSettingsDir) { this.evaluatedZapSettingsDir = evaluatedZapSettingsDir; }

    /* Session Management */
    private final boolean autoLoadSession;

    public boolean getAutoLoadSession() { return autoLoadSession; }

    private final String loadSession; /* Filename to load ZAProxy session. Contains the absolute path to the session */

    public String getLoadSession() { return loadSession; }

    private final String sessionFilename; /* Filename to save ZAPJ session. It can contain a relative path. */

    public String getSessionFilename() { return sessionFilename; }

    private String evaluatedSessionFilename;

    public String getEvaluatedSessionFilename() { return evaluatedSessionFilename; }

    public void setEvaluatedSessionFilename(String evaluatedSessionFilename) { this.evaluatedSessionFilename = evaluatedSessionFilename; }

    /* Session Properties */
    private final String contextName; /* Context name to use for the session */

    public String getContextName() { return contextName; }

    private String evaluatedContextName; /*  */

    public String getEvaluatedContextName() { return evaluatedContextName; }

    public void setEvaluatedContextName(String evaluatedContextName) { this.evaluatedContextName = evaluatedContextName; }

    private final String excludedURL; /* Exclude URI from context */

    public String getExcludedURL() { return excludedURL; }

    private String evaluatedExcludedURL;

    public String getEvaluatedExcludedURL() { return evaluatedExcludedURL; }

    public void setEvaluatedExcludedURL(String evaluatedExcludedURL) { this.evaluatedExcludedURL = evaluatedExcludedURL; }

    private final String includedURL; /* Include URI in context */

    public String getIncludedURL() { return includedURL; }

    private String evaluatedIncludedURL;

    public String getEvaluatedIncludedURL() { return evaluatedIncludedURL; }

    public void setEvaluatedIncludedURL(String evaluatedIncludedURL) { this.evaluatedIncludedURL = evaluatedIncludedURL; }

    /* Session Properties >> Authentication */
    /* Authentication information for conducting spider, AJAX spider or scan as a user */
    private boolean authMode; /*  */

    public boolean getAuthMode() { return authMode; }

    public void setAuthMode(boolean authMode) { this.authMode = authMode; }

    private final String username; /* Username for the defined user (form based authentication) */

    public String getusername() { return username; }

    private final String password; /* Password for the defined user (form based authentication) */

    public String getpassword() { return password; }

    private final String loggedInIndicator; /* logged in indication */

    public String getLoggedInIndicator() { return loggedInIndicator; }

    private final String authMethod; /* the authentication method type (SCRIPT_BASED/FORM_BASED) */

    public String getAuthMethod() { return authMethod; }

    /* Session Properties >> Form-Based Authentication */
    private final String loginURL; /* login URI */

    public String getLoginURL() { return loginURL; }

    private final String usernameParameter; /* username post data parameter (form based authentication) */

    public String getUsernameParameter() { return usernameParameter; }

    private final String passwordParameter; /* password post data parameter (form based authentication) */

    public String getpasswordParameter() { return passwordParameter; }

    private final String extraPostData; /* extra post data needed to authenticate the user (form based authentication) */

    public String getExtraPostData() { return extraPostData; }

    /* Session Properties >> Script-Based Authentication */
    private final String authScript; /* Authentication script name used (script based authentication) */

    public String getAuthScript() { return authScript; }

    private final String protectedPages; /* extra post data needed to authenticate the user (form based authentication) */

    public String getProtectedPages() { return protectedPages; }

    /**
     * List of all Authentication Script Parameters ArrayList because it needs to be Serializable (whereas List is not Serializable)
     */
    private final ArrayList<ZAPAuthScriptParam> authScriptParams;

    public List<ZAPAuthScriptParam> getAuthScriptParams() { return authScriptParams; }

    /* Attack Mode */
    private String targetURL; /* URL to attack by ZAPJ */

    public String getTargetURL() { return targetURL; }

    public void setTargetURL(String targetURL) { this.targetURL = targetURL; }

    private String evaluatedTargetURL; /* URL to attack by ZAPJ */

    public String getEvaluatedTargetURL() { return evaluatedTargetURL; }

    public void setEvaluatedTargetURL(String evaluatedTargetURL) { this.evaluatedTargetURL = evaluatedTargetURL; }

    /* Attack Mode >> Spider Scan */
    /*****************************/
    private final boolean spiderScanURL;

    public boolean getSpiderScanURL() { return spiderScanURL; }

    private final boolean spiderScanRecurse;

    public boolean getSpiderScanRecurse() { return spiderScanRecurse; }

    private final boolean spiderScanSubtreeOnly;

    public boolean getSpiderScanSubtreeOnly() { return spiderScanSubtreeOnly; }

    private final int spiderScanMaxChildrenToCrawl;

    public int getSpiderScanMaxChildrenToCrawl() { return spiderScanMaxChildrenToCrawl; }
    /*****************************/

    /* Attack Mode >> AJAX Spider */
    /*****************************/
    private final boolean ajaxSpiderURL;

    public boolean getAjaxSpiderURL() { return ajaxSpiderURL; }

    private final boolean ajaxSpiderInScopeOnly;

    public boolean getAjaxSpiderInScopeOnly() { return ajaxSpiderInScopeOnly; }
    /*****************************/

    /* Attack Mode >> Active Scan */
    /*****************************/
    private final boolean activeScanURL;

    public boolean getActiveScanURL() { return activeScanURL; }

    private final boolean activeScanRecurse;

    public boolean getActiveScanRecurse() { return activeScanRecurse; }

    private final String activeScanPolicy; /* The file policy to use for the scan. It contains only the policy name (without extension) */

    public String getActiveScanPolicy() { return activeScanPolicy; }
    /*****************************/

    /* Finalize Run */
    /* Finalize Run >> Generate Report(s) */
    /*****************************/
    private final boolean generateReports; /* Save reports or not */

    public boolean getGenerateReports() { return generateReports; }

    private boolean deleteReports;

    public boolean getDeleteReports() { return deleteReports; }

    private String reportFilename; /* Filename for ZAPJ reports. It can contain a relative path or environment variable */

    public String getReportFilename() { return reportFilename; }

    private String evaluatedReportFilename; /* Filename for ZAPJ reports. It can contain a relative path (it's derived from the one above) */
    // get and set of the new field which will contain the evaluated value of the report file name. So the environment variable will persist after each build

    public String getEvaluatedReportFilename() { return evaluatedReportFilename; }

    public void setEvaluatedReportFilename(String evaluatedReportFilename) { this.evaluatedReportFilename = evaluatedReportFilename; }

    private final String selectedReportMethod; /* Choose between default ZAP report or Export Report plugin */

    public String getSelectedReportMethod() { return selectedReportMethod; }

    /* Default ZAP Report */
    private final ArrayList<String> selectedReportFormats; /* List of chosen format for reports. ArrayList because it needs to be Serializable (whereas List is not Serializable) */

    public List<String> getSelectedReportFormats() { return selectedReportFormats; }

    /* Export Report Plugin */
    private final ArrayList<String> selectedExportFormats; /* List of chosen format for reports. ArrayList because it needs to be Serializable (whereas List is not Serializable) */

    public List<String> getSelectedExportFormats() { return selectedExportFormats; }

    private final String exportreportTitle;

    public String getExportreportTitle() { return exportreportTitle; }

    private String evaluatedExportreportTitle;

    public String getEvaluatedExportreportTitle() { return evaluatedExportreportTitle; }

    public void setEvaluatedExportreportTitle(String evaluatedExportreportTitle) { this.evaluatedExportreportTitle = evaluatedExportreportTitle; }

    private final String exportreportBy;

    public String getExportreportBy() { return exportreportBy; }

    private final String exportreportFor;

    public String getExportreportFor() { return exportreportFor; }

    private final String exportreportScanDate;

    public String getExportreportScanDate() { return exportreportScanDate; }

    private final String exportreportReportDate;

    public String getExportreportReportDate() { return exportreportReportDate; }

    private final String exportreportScanVersion;

    public String getExportreportScanVersion() { return exportreportScanVersion; }

    private final String exportreportReportVersion;

    public String getExportreportReportVersion() { return exportreportReportVersion; }

    private final String exportreportReportDescription;

    public String getExportreportReportDescription() { return exportreportReportDescription; }

    private final boolean exportreportAlertHigh;

    public boolean getExportreportAlertHigh() { return exportreportAlertHigh; }

    private final boolean exportreportAlertMedium;

    public boolean getExportreportAlertMedium() { return exportreportAlertMedium; }

    private final boolean exportreportAlertLow;

    public boolean getExportreportAlertLow() { return exportreportAlertLow; }

    private final boolean exportreportAlertInformational;

    public boolean getExportreportAlertInformational() { return exportreportAlertInformational; }

    private final boolean exportreportCWEID;

    public boolean getExportreportCWEID() { return exportreportCWEID; }

    private final boolean exportreportWASCID;

    public boolean getExportreportWASCID() { return exportreportWASCID; }

    private final boolean exportreportDescription;

    public boolean getExportreportDescription() { return exportreportDescription; }

    private final boolean exportreportOtherInfo;

    public boolean getExportreportOtherInfo() { return exportreportOtherInfo; }

    private final boolean exportreportSolution;

    public boolean getExportreportSolution() { return exportreportSolution; }

    private final boolean exportreportReference;

    public boolean getExportreportReference() { return exportreportReference; }

    private final boolean exportreportRequestHeader;

    public boolean getExportreportRequestHeader() { return exportreportRequestHeader; }

    private final boolean exportreportResponseHeader;

    public boolean getExportreportResponseHeader() { return exportreportResponseHeader; }

    private final boolean exportreportRequestBody;

    public boolean getExportreportRequestBody() { return exportreportRequestBody; }

    private final boolean exportreportResponseBody;

    public boolean getExportreportResponseBody() { return exportreportResponseBody; }

    /*****************************/

    /* Finalize Run >> Create JIRA Issue(s) */
    /*****************************/
    /* List of all parameters used for the ZAP add-on jiraIssueCreater */
    /* gets and sets the values from the credentials and base URI method call is from ZAPJBuilder */
    private final boolean jiraCreate; /* create JIRA'S or not */

    public boolean getJiraCreate() { return jiraCreate; }

    private String jiraBaseURL;

    public void setJiraBaseURL(String jiraBaseURL) { this.jiraBaseURL = jiraBaseURL; }

    private String jiraUsername;

    public void setJiraUsername(String jiraUsername) { this.jiraUsername = jiraUsername; }

    private String jiraPassword;

    public void setJiraPassword(String jiraPassword) { this.jiraPassword = jiraPassword; }

    private final String jiraProjectKey; /* The JIRA project key */

    public String getJiraProjectKey() { return jiraProjectKey; }

    private final String jiraAssignee;/* The JIRA assignee */

    public String getJiraAssignee() { return jiraAssignee; }

    private final boolean jiraAlertHigh; /* select alert type high */

    public boolean getJiraAlertHigh() { return jiraAlertHigh; }

    private final boolean jiraAlertMedium; /* select alert type medium */

    public boolean getJiraAlertMedium() { return jiraAlertMedium; }

    private final boolean jiraAlertLow; /* select alert type low */

    public boolean getJiraAlertLow() { return jiraAlertLow; }

    private final boolean jiraFilterIssuesByResourceType; /* Filter issues by resource type */

    public boolean getFiraFilterIssuesByResourceType() { return jiraFilterIssuesByResourceType; }
    /*****************************/
}
