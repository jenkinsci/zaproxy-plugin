/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 ZAP Jenkins Plugin and its related class files.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
 * @Mostafa AbdelMoez
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
    private static final String NAME_POLICIES_DIR_ZAP = "policies";
    private static final String NAME_SCRIPTS_DIR_ZAP = "scripts";
    private static final String NAME_AUTH_SCRIPTS_DIR_ZAP = "authentication";

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
            boolean generateReports, List<String> selectedReportFormats, String reportFilename, 
            boolean createJiras, String jiraProjectKey, String jiraAssignee, boolean alertHigh, boolean alertMedium, boolean alertLow, boolean filterIssuesByResourceType, 
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
        this.selectedReportFormats = selectedReportFormats != null ? new ArrayList<String>(selectedReportFormats) : new ArrayList<String>();
        this.reportFilename = reportFilename;

        /* Finalize Run >> Create JIRA Issue(s) */
        this.createJiras = createJiras;
        this.jiraProjectKey = jiraProjectKey;
        this.jiraAssignee = jiraAssignee;
        this.alertHigh = alertHigh;
        this.alertMedium = alertMedium;
        this.alertLow = alertLow;
        this.filterIssuesByResourceType = filterIssuesByResourceType;
        /* Other */
        this.cmdLinesZAP = cmdLinesZAP != null ? new ArrayList<ZAPCmdLine>(cmdLinesZAP) : new ArrayList<ZAPCmdLine>();

        System.out.println(this.toString());
    }

    @Override
    public String toString() {
        String s = "";
        s += "Admin Configurations\n";
        s += "-------------------------------------------------------\n";
        s += "zapHost [" + zapHost + "]\n";
        s += "zapPort [" + zapPort + "]\n";
        s += "= zapHost [" + evaluatedZapHost + "]\n";
        s += "= zapPort [" + evaluatedZapPort + "]\n";
        s += "autoInstall [" + autoInstall + "]\n";
        s += "toolUsed [" + toolUsed + "]\n";
        s += "zapHome [" + zapHome + "]\n";
        s += "jdk [" + jdk + "]\n";
        s += "timeout [" + timeout + "]\n";
        s += "\n";
        s += "ZAP Settings\n";
        s += "-------------------------------------------------------\n";
        s += "zapSettingsDir [" + zapSettingsDir + "]\n";
        s += "= zapSettingsDir [" + evaluatedZapSettingsDir + "]\n";
        s += "\n";
        s += "Load Session\n";
        s += "-------------------------------------------------------\n";
        s += "autoLoadSession [" + autoLoadSession + "]\n";
        s += "loadSession [" + loadSession + "]\n";
        s += "sessionFilename [" + sessionFilename + "]\n";
        s += "= persistSession [" + evaluatedSessionFilename + "]\n";
        s += "\n";
        s += "Session Properties\n";
        s += "-------------------------------------------------------\n";
        s += "contextName [" + contextName + "]\n";
        s += "= contextName [" + evaluatedContextName + "]\n";
        s += "includedURL [" + includedURL + "]\n";
        s += "excludedURL [" + excludedURL + "]\n";
        s += "= includedURL [" + evaluatedIncludedURL + "]\n";
        s += "= excludedURL [" + evaluatedExcludedURL + "]\n";
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
        s += "protectedPages [" + protectedPages + "]\n";
        s += "\n";
        s += "Attack Modes\n";
        s += "-------------------------------------------------------\n";
        s += "targetURL [" + targetURL + "]\n";
        s += "= targetURL [" + evaluatedTargetURL + "]\n";
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
        s += "selectedReportFormats [" + selectedReportFormats + "]\n";
        s += "reportFilename [" + evaluatedReportFilename + "]\n";
        s += "\n";
        s += "Finalize Run >> Create JIRA Issue(s)\n";
        s += "-------------------------------------------------------\n";
        s += "createJiras [" + createJiras + "]\n";
        s += "jiraBaseURL [" + jiraBaseURL + "]\n";
        s += "jiraUsername [" + jiraUsername + "]\n";
        s += "jiraProjectKey [" + jiraProjectKey + "]\n";
        s += "jiraAssignee [" + jiraAssignee + "]\n";
        s += "alertHigh [" + alertHigh + "]\n";
        s += "alertMedium [" + alertMedium + "]\n";
        s += "alertLow [" + alertLow + "]\n";
        s += "filterIssuesByResourceType[" + filterIssuesByResourceType + "]\n";
        return s;
    }

    /**
     * Message builder method that accepts a list of arguments. Used for internationalized messages.
     *
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkin
     * @param message
     *            of TYPE String DESC: The message to display in the log, injected values are indicated by {0}, {1}, etc.
     * @param args
     *            of TYPE String... DESC: The injected values to go into the message.
     */
    private void loggerMessage(BuildListener listener, String message, String... args) {
        MessageFormat mf = new MessageFormat(message);
        listener.getLogger().println(mf.format(args));
    }

    // TODO
    private String indent(String str, int indent) {
        String temp = "";
        for (int i = 0; i < indent; i++)
            for (int j = 0; j < 4; j++)
                temp = temp + "\0";
        return temp + str;
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
                    if (tool.getName().equals(toolUsed)) {
                        if (tool instanceof NodeSpecific) tool = (ToolInstallation) ((NodeSpecific<?>) tool).forNode(node, listener);
                        if (tool instanceof EnvironmentSpecific) tool = (ToolInstallation) ((EnvironmentSpecific<?>) tool).forEnvironment(env);
                        installPath = tool.getHome();

                        return installPath;
                    }
        }
        else installPath = build.getEnvironment(listener).get(zapHome);
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

        if (zapProgram == null || zapProgram.isEmpty()) throw new IllegalArgumentException("zapProgram is missing");
        else loggerMessage(listener, "zapProgram = [ {0} ]", zapProgram);

        EnvVars envVars = build.getEnvironment(listener);

        // The system environment variable will have been expanded at this point already, if using
        // Environment Injector plugin then you need to expand once more.
        // excludedURL will look like [${EXCLUDED_A}, derp.com, ${EXCLUDED_B}, ${TEST_ID}]
        // while evaluatedExcludedURL will look like [${EXCLUDED_A}, derp.com, ${EXCLUDED_B}, www.systemenv.com]
        // it does not matter which you expand in this case because neither can work if 'Start ZAProxy in a pre-build step' is chosen

        evaluatedZapHost = envVars.expand(evaluatedZapHost);
        if (evaluatedZapHost == null || evaluatedZapHost.isEmpty()) throw new IllegalArgumentException("ZAP Host is missing");
        else loggerMessage(listener, "Expanded host = [ {0} ]", evaluatedZapHost);

        evaluatedZapPort = Integer.parseInt(envVars.expand(String.valueOf(evaluatedZapPort)));
        if (evaluatedZapPort < 0) throw new IllegalArgumentException("ZAP Port is less than 0");
        else loggerMessage(listener, "Expanded port = [ {0} ]", String.valueOf(evaluatedZapPort));

        evaluatedContextName = envVars.expand(evaluatedContextName);
        if (evaluatedContextName == null || evaluatedContextName.isEmpty()) throw new IllegalArgumentException("Expanded contextName is missing " + evaluatedContextName);
        else loggerMessage(listener, "Expanded contextName = [ {0} ]", envVars.expand(evaluatedContextName));

        evaluatedZapSettingsDir = envVars.expand(evaluatedZapSettingsDir);
        if (evaluatedZapSettingsDir == null || evaluatedZapSettingsDir.isEmpty()) throw new IllegalArgumentException("Expanded zapSettingsDir is missing " + evaluatedZapSettingsDir);
        else loggerMessage(listener, "Expanded zapSettingsDir = [ {0} ]", envVars.expand(evaluatedZapSettingsDir));

        evaluatedIncludedURL = envVars.expand(evaluatedIncludedURL);
        if (evaluatedIncludedURL == null || evaluatedIncludedURL.isEmpty()) throw new IllegalArgumentException("Expanded includedURL is missing " + evaluatedIncludedURL);
        else loggerMessage(listener, "Expanded includeURL = [ {0} ]", envVars.expand(evaluatedIncludedURL));

        evaluatedExcludedURL = envVars.expand(evaluatedExcludedURL);
        loggerMessage(listener, "Expanded excludedURL = [ {0} ]", envVars.expand(evaluatedExcludedURL));

        evaluatedTargetURL = envVars.expand(evaluatedTargetURL);
        if (evaluatedTargetURL == null || evaluatedTargetURL.isEmpty()) throw new IllegalArgumentException("Expanded targetURL is missing " + evaluatedTargetURL);
        else loggerMessage(listener, "Expanded targetURL = [ {0} ]", evaluatedTargetURL);

        evaluatedSessionFilename = envVars.expand(evaluatedSessionFilename);
        loggerMessage(listener, "Expanded sessionFilename = [ {0} ]", envVars.expand(evaluatedSessionFilename));

        /* createJiras is enabled */
        if (getcreateJiras() == true) {

            /* Minimum : the url is needed */
            if (jiraBaseURL == null || jiraBaseURL.isEmpty()) throw new IllegalArgumentException("Jira Base URL not Found");
            else loggerMessage(listener, "jiraBaseURL = [ {0} ]", jiraBaseURL);

            /* the username can be empty */
            if (jiraUsername == null) throw new IllegalArgumentException("Jira User name not Found");
            else loggerMessage(listener, "jiraUsername = [ {0} ]", jiraUsername);

            /* the password can be empty */
            if (jiraPassword == null) throw new IllegalArgumentException("Jira password not Found");
        }
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
        checkParams(build, listener);

        FilePath ws = build.getWorkspace();
        if (ws == null) {
            Node node = build.getBuiltOn();
            if (node == null) throw new NullPointerException("No such build node: " + build.getBuiltOnStr());
            throw new NullPointerException("No workspace from node " + node + " which is computer " + node.toComputer() + " and has channel " + node.getChannel());
        }

        /* Contains the absolute path to ZAP program */
        FilePath zapPathWithProgName = new FilePath(ws.getChannel(), zapProgram + getZAPProgramNameWithSeparator(build));
        loggerMessage(listener, "Start ZAP [ {0} ]", zapPathWithProgName.getRemote());

        /* Command to start ZAProxy with parameters */
        List<String> cmd = new ArrayList<String>();
        cmd.add(zapPathWithProgName.getRemote());
        cmd.add(CMD_LINE_DAEMON);
        cmd.add(CMD_LINE_HOST);
        cmd.add(evaluatedZapHost);
        cmd.add(CMD_LINE_PORT);
        cmd.add(String.valueOf(evaluatedZapPort));
        cmd.add(CMD_LINE_CONFIG);
        cmd.add(CMD_LINE_API_KEY + "=" + API_KEY);

        /* Set the default directory used by ZAP if it's defined and if a scan is provided */
        if (getActiveScanURL() && evaluatedZapSettingsDir != null && !evaluatedZapSettingsDir.isEmpty()) {
            cmd.add(CMD_LINE_DIR);
            cmd.add(evaluatedZapSettingsDir);
        }

        /* Adds command line arguments if it's provided */
        if (!evaluatedCmdLinesZap.isEmpty()) addZapCmdLine(cmd);

        EnvVars envVars = build.getEnvironment(listener);
        /* on Windows environment variables are converted to all upper case, but no such conversions are done on Unix, so to make this cross-platform, convert variables to all upper cases. */
        for (Map.Entry<String, String> e : build.getBuildVariables().entrySet())
            envVars.put(e.getKey(), e.getValue());
        FilePath workDir = new FilePath(ws.getChannel(), zapProgram);

        /* JDK choice */
        computeJdkToUse(build, listener, envVars);

        /* Launch ZAP process on remote machine (on master if no remote machine) */
        Proc proc = launcher.launch().cmds(cmd).envs(envVars).stdout(listener).pwd(workDir).start();

        /* Call waitForSuccessfulConnectionToZap(int, BuildListener) remotely */
        build.getWorkspace().act(new WaitZAPDriverInitCallable(this, listener));

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
    private void addZapCmdLine(List<String> list) {
        for (ZAPCmdLine zapCmd : evaluatedCmdLinesZap) {
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
    private void addZAPAuthScriptParam(StringBuilder s) throws UnsupportedEncodingException {
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
    private void waitForSuccessfulConnectionToZap(int timeout, BuildListener listener) {
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
    private void saveReport(ZAPReport reportFormat, BuildListener listener, FilePath workspace, ClientApi clientApi) throws IOException, ClientApiException {
        final String fullFileName = evaluatedReportFilename + "." + reportFormat.getFormat();
        File reportsFile = new File(workspace.getRemote(), fullFileName);
        FileUtils.writeByteArrayToFile(reportsFile, reportFormat.generateReport(clientApi, API_KEY));
        loggerMessage(listener, "File [ {0} ] saved", reportsFile.getAbsolutePath());
    }

    /**
     * Execute ZAPJ method following build's setup and stop ZAP at the end.
     *
     * @param workspace
     *            of TYPE: FilePath DESC: a {@link FilePath} representing the build's workspace
     * @param listener
     *            of TYPE: BuildListener DESC: the listener to display log during the job execution in Jenkins
     * @return of TYPE: boolean DESC: true if no exception is caught, false otherwise.
     */
    // public boolean executeZAP(FilePath workspace, BuildListener listener) {
    // ClientApi zapClientAPI = new ClientApi(zapHost, zapPort);
    // boolean buildSuccess = true;
    // loggerMessage(listener, "zap home : { 0 }", getZapHome());
    // loggerMessage(listener, "timeout in sec : { 0 }", String.valueOf(getTimeout()));
    // loggerMessage(listener, "session file : { 0 }", getFilenameLoadSession());
    // loggerMessage(listener, "context name : { 0 }", getContextName());
    // loggerMessage(listener, "include url : { 0 }", getIncludedURL());
    // loggerMessage(listener, "exclude url : { 0 }", getExcludedURL());
    // loggerMessage(listener, "authMode : { 0 }", String.valueOf(getAuthMode()));
    // loggerMessage(listener, "spider : { 0 }", String.valueOf(getSpiderScanURL()));
    // loggerMessage(listener, "ajax : { 0 }", String.valueOf(getAjaxSpiderURL()));
    // loggerMessage(listener, "active : { 0 }", String.valueOf(getActiveScanURL()));
    //
    // return buildSuccess;
    // }
    public boolean executeZAP(FilePath workspace, BuildListener listener) {
        ClientApi zapClientAPI = new ClientApi(evaluatedZapHost, evaluatedZapPort);
        boolean buildSuccess = true;

        try {
            /*
             * ===== | LOAD SESSION | =====
             */
            if (autoLoadSession && loadSession != null && loadSession.length() != 0) {
                File sessionFile = new File(loadSession);
                loggerMessage(listener, "Load session at [ {0} ]", sessionFile.getAbsolutePath());
                /*
                 * @class org.zaproxy.clientapi.gen.Core
                 * 
                 * @method loadSession
                 * 
                 * @param String apikey
                 * 
                 * @param String name
                 * 
                 * @throws ClientApiException
                 */
                zapClientAPI.core.loadSession(API_KEY, sessionFile.getAbsolutePath());
            }
            else if (!autoLoadSession) {
                loggerMessage(listener, "Skip loadSession");
                if (sessionFilename == null || sessionFilename.isEmpty()) {
                    buildSuccess = false;
                    listener.getLogger().println("Persist Session: No Session has been specified, build marked as failure.");                
                }
            }
            else {
                buildSuccess = false;
                loggerMessage(listener, "Load Session: No Session has been specified, build marked as failure.");
            }

            /*
             * ===== | SET UP CONTEXT | =====
             */

            // setup context
            
            if (buildSuccess) {
                this.contextId = setUpContext(listener, evaluatedContextName, evaluatedIncludedURL, evaluatedExcludedURL, zapClientAPI);

                loggerMessage(listener, "AUTHENTICATION ENABLED : {0}", String.valueOf(authMode).toUpperCase());

                // if (getSpiderScanURL()) {
                // if (!authMode) {
                // loggerMessage(listener, "Spider the site [ {0} ]", evaluatedTargetURL);
                // }
                // else if (authMode) {
                // loggerMessage(listener, "Spider the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // }
                // spiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else {
                // if (!authMode) {
                // loggerMessage(listener, "Skip spidering the site [ {0} ]", evaluatedTargetURL);
                // }
                // else if (authMode) {
                // loggerMessage(listener, "Skip spidering the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // }
                // }

                if (authMode) if (authMethod.equals(FORM_BASED)) setUpAuthentication(listener, zapClientAPI, loginURL, username, password, loggedInIndicator, extraPostData, authMethod, usernameParameter, passwordParameter, null, null);
                else if (authMethod.equals(SCRIPT_BASED)) setUpAuthentication(listener, zapClientAPI, loggedInIndicator, username, password, loggedInIndicator, extraPostData, authMethod, null, null, authScript, protectedPages);
                spiderURL(listener, zapClientAPI, evaluatedTargetURL);
                ajaxSpiderURL(listener, zapClientAPI, evaluatedTargetURL);
                scanURL(listener, zapClientAPI, evaluatedTargetURL);

                // if (!authMode) {
                // if (getSpiderScanURL()) {
                // loggerMessage(listener, "Spider the site [ {0} ]", evaluatedTargetURL);
                // spiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else loggerMessage(listener, "Skip spidering the site [ {0} ]", evaluatedTargetURL);
                // }
                // else if (authMode) {
                // loggerMessage(listener, "Setting up Authentication");
                //
                // if (authMethod.equals(FORM_BASED)) setUpAuthentication(listener, zapClientAPI, loginURL, username, password, loggedInIndicator, extraPostData, authMethod, usernameParameter, passwordParameter, null, null);
                // else if (authMethod.equals(SCRIPT_BASED)) setUpAuthentication(listener, zapClientAPI, loggedInIndicator, username, password, loggedInIndicator, extraPostData, authMethod, null, null, authScript, protectedPages);
                //
                // if (getSpiderScanURL()) {
                // loggerMessage(listener, "Spider the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // spiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else loggerMessage(listener, "Skip spidering the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                //
                // }

                // If it's not authenticated scan
                // if (!authMode) {
                //
                // loggerMessage(listener, "SCANMOD : NOT_AUTHENTICATED");
                //
                // Non authenticated mode : spider url, ajax spider url, scan url
                /*
                 * ===== | SPIDER URL | =====
                 */
                // if (getSpiderScanURL()) {
                // loggerMessage(listener, "Spider the site [ {0} ]", evaluatedTargetURL);
                // spiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else loggerMessage(listener, "Skip spidering the site [ {0} ]", evaluatedTargetURL);

                /*
                 * ===== | AJAX SPIDER URL | =====
                 */
                // if (getAjaxSpiderURL()) {
                // loggerMessage(listener, "Ajax Spider the site [ {0} ]", evaluatedTargetURL);
                // ajaxSpiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else loggerMessage(listener, "Skip Ajax spidering the site [ {0} ]", evaluatedTargetURL);

                /*
                 * ===== | SCAN URL | =====
                 */
                // if (getActiveScanURL()) {
                // loggerMessage(listener, "Scan the site [ {0} ]", evaluatedTargetURL);
                // scanURL(evaluatedTargetURL, listener, zapClientAPI);
                // }
                // else loggerMessage(listener, "Skip scanning the site [ {0} ]", evaluatedTargetURL);
                // }

                // else if (scanMode.equals("AUTHENTICATED")) {
                // else if (authMode) {
                // // Authenticated mod : spider url as user, ajax spider url as
                // // user, scan url as user
                // loggerMessage(listener, "SCANMOD : AUTHENTICATED");
                // loggerMessage(listener, "SCANMOD : " + authMethod);

                // loggerMessage(listener, "Setting up Authentication");

                // if (authMethod.equals(FORM_BASED)) setUpAuthentication(listener, zapClientAPI, loginURL, username, password, loggedInIndicator, extraPostData, authMethod, usernameParameter, passwordParameter, null, null);
                // else if (authMethod.equals(SCRIPT_BASED)) setUpAuthentication(listener, zapClientAPI, loggedInIndicator, username, password, loggedInIndicator, extraPostData, authMethod, null, null, authScript, protectedPages);

                /*
                 * ===== | SPIDER AS USER | =====
                 */

                // if (getSpiderScanURL()) {
                // loggerMessage(listener, "Spider the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // spiderURLAsUser(listener, zapClientAPI, evaluatedTargetURL, contextId, userId);
                // }
                // else loggerMessage(listener, "Skip spidering the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);

                /*
                 * ===== | AJAX SPIDER URL AS USER | =====
                 */
                // if (getAjaxSpiderURL()) {
                // loggerMessage(listener, "Ajax Spider the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // ajaxSpiderURL(listener, zapClientAPI, evaluatedTargetURL);
                // }
                // else loggerMessage(listener, "Skip Ajax spidering the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);

                /*
                 * ===== | SCAN URL AS USER | =====
                 */
                // if (getActiveScanURL()) {
                // loggerMessage(listener, "Scan the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // scanURLAsUser(evaluatedTargetURL, listener, zapClientAPI, contextId, userId);
                // }
                // else loggerMessage(listener, "Skip scanning the site [ {0} ] as user [ {1} ]", evaluatedTargetURL, username);
                // }

                /*
                 * ===== | SAVE REPORTS | =====
                 */
                if (generateReports) for (String format : selectedReportFormats) {
                    ZAPReport report = ZAPReportCollection.getInstance().getMapFormatReport().get(format);
                    saveReport(report, listener, workspace, zapClientAPI);
                }

                /*
                 * ===== | CREATE JIRA ISSUES | =====
                 */
                if (createJiras) {
                    loggerMessage(listener, "===== | Creating JIRA Tickets | =====");
                    Map<String, String> map = null;
                    map = new HashMap<String, String>();

                    if (API_KEY != null) map.put("apikey", API_KEY);
                    map.put("jiraBaseURL", jiraBaseURL);
                    map.put("jiraUserName", jiraUsername);
                    map.put("jiraPassword", jiraPassword);
                    map.put("jiraProjectKey", jiraProjectKey);
                    // map.put("jiraUserName",jiraUserName);
                    map.put("jiraAssignee", jiraAssignee);
                    map.put("high", returnCheckedStatus(alertHigh));
                    map.put("medium", returnCheckedStatus(alertMedium));
                    map.put("low", returnCheckedStatus(alertLow));
                    map.put("filterIssuesByResourceType", returnCheckedStatus(filterIssuesByResourceType));

                    loggerMessage(listener, "===== | Initialized Variables | =====");

                    loggerMessage(listener, indent("Api key  : {0}", 1), API_KEY);
                    loggerMessage(listener, indent("Base URL  : {0}", 1), jiraBaseURL);
                    loggerMessage(listener, indent("UserName  : {0}", 1), jiraUsername);
                    loggerMessage(listener, indent("Project key  : {0}", 1), jiraProjectKey);
                    loggerMessage(listener, indent("Assignee  : {0}", 1), jiraAssignee);
                    loggerMessage(listener, indent("Export High alerts  : {0}", 1), Boolean.toString(alertHigh));
                    loggerMessage(listener, indent("Export Medium alerts  : {0}", 1), Boolean.toString(alertMedium));
                    loggerMessage(listener, indent("Export Low alerts  : {0}", 1), Boolean.toString(alertLow));
                    loggerMessage(listener, indent("Filter by resource Type  : {0}", 1), Boolean.toString(filterIssuesByResourceType));

                    try {

                        /*
                         * @class org.zaproxy.clientapi.core.ClientApi
                         * 
                         * @method callApi
                         * 
                         * @param String component
                         * 
                         * @param String type
                         * 
                         * @param String method
                         * 
                         * @param Map<String, String> params
                         * 
                         * @throws ClientApiException
                         */
                        zapClientAPI.callApi("jiraIssueCreater", "action", "createJiraIssues", map);

                    }
                    catch (ClientApiException e) {

                        listener.getLogger().println(e.getMessage());
                    }

                }
                else listener.getLogger().println("Skipped creating jiras");

                /*
                 * ===== | SAVE SESSION | =====
                 */
                if (!autoLoadSession) {
                    if (sessionFilename != null && !sessionFilename.isEmpty()) {
                        File sessionFile = new File(workspace.getRemote(), sessionFilename);
                        listener.getLogger().println("Save session to [" + sessionFile.getAbsolutePath() + "]");

                        // Path creation if it doesn't exist
                        if (!sessionFile.getParentFile().exists()) sessionFile.getParentFile().mkdirs();

                        /*
                         * @class org.zaproxy.clientapi.gen.Core
                         * 
                         * @method saveSession
                         * 
                         * @param String apikey
                         * 
                         * @param String name
                         * 
                         * @param String overwrite
                         * 
                         * @throws ClientApiException
                         */
                        zapClientAPI.core.saveSession(API_KEY, sessionFile.getAbsolutePath(), "true");
                    }
                }
                else
                {
                    listener.getLogger().println("Skip persistSession because a session was loaded.");
                }

                listener.getLogger().println("Total alerts = " + zapClientAPI.core.numberOfAlerts("").toString(2));
                listener.getLogger().println("Total messages = " + zapClientAPI.core.numberOfMessages("").toString(2));
            }
        }
        catch (Exception e) {
            listener.error(ExceptionUtils.getStackTrace(e));
            buildSuccess = false;
        }
        finally {
            try {
                // stopZAP(this, zapClientAPI, listener);
                stopZAP(zapClientAPI, listener);
            }
            catch (ClientApiException e) {
                listener.error(ExceptionUtils.getStackTrace(e));
                buildSuccess = false;
            }
        }
        return buildSuccess;
    }

    /**
     * method used to return the checked state inside CREATE JIRA ISSUES
     **/
    private String returnCheckedStatus(boolean checkedStatus) { return checkedStatus ? "1" : "0"; }

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
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @return the context ID of the context
     * @throws ClientApiException
     */
    private String setUpContext(BuildListener listener, String context, String includedURL, String excludedURL, ClientApi zapClientAPI) throws ClientApiException {

        includedURL = includedURL.trim();

        String contextName;
        if (context == null || context.isEmpty()) contextName = "context1";
        else contextName = context;

        // name of the Context to be created

        // @Deprecated
        // String contextURL="\\Q"+url+"\\E.*";//url to be added to the context
        // (the same url given by the user to be scanned)
        String contextURL = includedURL;// url to be added to the context (the
                                        // same url given by the user to be
                                        // scanned)

        String contextIdTemp;

        // Create new context
        // method signature : newContext(String apikey,String contextname)
        // throws ClientApiException
        contextIdTemp = extractContextId(zapClientAPI.context.newContext(API_KEY, contextName));

        /*
         * @class org.zaproxy.clientapi.gen.Context
         * 
         * @method includeInContext
         * 
         * @param String apikey
         * 
         * @param String contextname
         * 
         * @param String regex
         * 
         * @throws ClientApiException
         */
        zapClientAPI.context.includeInContext(API_KEY, contextName, contextURL);
        listener.getLogger().println("URL " + includedURL + " added to Context [" + contextIdTemp + "]");

        // excluded urls from context
        if (!excludedURL.equals("")) try {

            String[] urls = excludedURL.split("\n");
            String contextExcludedURL = "";// url to exclude from context like the log out url

            for (int i = 0; i < urls.length; i++) {
                urls[i] = urls[i].trim();
                if (!urls[i].isEmpty()) {
                    // contextExcludedURL="\\Q"+urls[i]+"\\E";
                    contextExcludedURL = urls[i];
                    zapClientAPI.context.excludeFromContext(API_KEY, contextName, contextExcludedURL);
                    listener.getLogger().println("URL exluded from context : " + urls[i]);
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
     * @param zapClientAPI
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
    private void setUpFormBasedAuth(BuildListener listener, ClientApi zapClientAPI, String contextId, String loginURL, String loggedInIndicator, String extraPostData, String usernameParameter, String passwordParameter) throws ClientApiException, UnsupportedEncodingException {

        String loginRequestData = usernameParameter + "={%username%}&" + passwordParameter + "={%password%}&" + extraPostData;

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
        zapClientAPI.authentication.setAuthenticationMethod(API_KEY, contextId, "formBasedAuthentication", formBasedConfig.toString());

        listener.getLogger().println("Authentication config: " + zapClientAPI.authentication.getAuthenticationMethod(contextId).toString(0));

        // end set auth method
        listener.getLogger().println("Form Based Authentication added to context");

        // add logged in indicator
        if (!loggedInIndicator.equals("")) {
            zapClientAPI.authentication.setLoggedInIndicator(API_KEY, contextId, loggedInIndicator);
            listener.getLogger().println("Logged in indicator " + loggedInIndicator + " added to context ");
        }
    }

    /**
     * set up script based authentication method for the created context
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
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
    private void setUpScriptBasedAuth(BuildListener listener, ClientApi zapClientAPI, String contextId, String loginURL, String loggedInIndicator, String extraPostData, String scriptName, String protectedPages) throws UnsupportedEncodingException, ClientApiException {

        // set script based authentication method
        // Prepare the configuration in a format similar to how URL parameters
        // are formed. This
        // means that any value we add for the configuration values has to be
        // URL encoded.
        StringBuilder scriptBasedConfig = new StringBuilder();
        scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
        if (!authScriptParams.isEmpty()) addZAPAuthScriptParam(scriptBasedConfig);

        // StringBuilder scriptBasedConfig = new StringBuilder();
        // scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
        // scriptBasedConfig.append("&loginUrl=").append(URLEncoder.encode(loginURL, "UTF-8"));
        // scriptBasedConfig.append("&protectedPages=").append(URLEncoder.encode(protectedPages, "UTF-8"));
        // scriptBasedConfig.append("&extraPostData=").append(URLEncoder.encode(extraPostData, "UTF-8"));
        // {"methodConfigParams":[{"name":"scriptName","mandatory":"true"},{"name":"scriptConfigParams","mandatory":"false"}]}

        listener.getLogger().println("Setting Script based authentication configuration as: " + scriptBasedConfig.toString());

        // TODO ASK ZAP DEV TEAM
        // ApiResponse
        // org.zaproxy.clientapi.gen.Authentication.setAuthenticationMethod(String
        // apikey, String contextid, String authmethodname, String
        // authmethodconfigparams) throws ClientApiException
        // it's possible to know more of authmethodconfigparams for each authentication method with http://localhost:8080/JSON/authentication/view/getAuthenticationMethodConfigParams/?authMethodName=scriptBasedAuthentication
        zapClientAPI.authentication.setAuthenticationMethod(API_KEY, contextId, "scriptBasedAuthentication", scriptBasedConfig.toString());

        /*
         * 2:14:01 PM - thc202: and optional 2:14:56 PM - thc202: that value is the indentation level when generating the string representation of the API response 2:14:57 PM - thc202: https://github.com/zaproxy/zap-api-java/blob/master/subprojects/zap-clientapi/src/main/java/org/zaproxy/clientapi/core/ApiResponseSet.java#L61
         *
         *
         */

        // https://github.com/zaproxy/zap-api-java/blob/master/subprojects/zap-clientapi/src/main/java/org/zaproxy/clientapi/core/ApiResponseSet.java#L61

        // no, the string (if outputted) would be shifted to the right one more level
        listener.getLogger().println("Authentication config: " + zapClientAPI.authentication.getAuthenticationMethod(contextId).toString(0));

        // add logged in idicator
        if (!loggedInIndicator.equals("")) {
            listener.getLogger().println("---------------------------------------");
            zapClientAPI.authentication.setLoggedInIndicator(API_KEY, contextId, loggedInIndicator);
        }
    }

    /**
     * set up user for the context and enable user
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
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
    private String setUpUser(BuildListener listener, ClientApi zapClientAPI, String username, String password, String contextId) throws ClientApiException, UnsupportedEncodingException {

        String userIdTemp;
        // add new user and authentication details
        // Make sure we have at least one user
        // extract user id
        userIdTemp = extractUserId(zapClientAPI.users.newUser(API_KEY, contextId, username));

        // Prepare the configuration in a format similar to how URL parameters
        // are formed. This
        // means that any value we add for the configuration values has to be
        // URL encoded.
        StringBuilder userAuthConfig = new StringBuilder();
        if ( authMethod.equals(SCRIPT_BASED)) { userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8")); userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8")); }
        else { userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8")); userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8")); }
        String authCon = userAuthConfig.toString();
        /*
         * @class org.zaproxy.clientapi.gen.Users
         * 
         * @method setAuthenticationCredentials
         * 
         * @param String apikey
         * 
         * @param String contextid
         * 
         * @param String String userid
         * 
         * @param String String authcredentialsconfigparams
         * 
         * @throws ClientApiException
         */
        zapClientAPI.users.setAuthenticationCredentials(API_KEY, contextId, userIdTemp, authCon);

        listener.getLogger().println("New user added. username :" + username);

        /*
         * @class org.zaproxy.clientapi.gen.Users
         * 
         * @method setUserEnabled
         * 
         * @param String apikey
         * 
         * @param String contextid
         * 
         * @param String String userid
         * 
         * @param String String enabled
         * 
         * @throws ClientApiException
         */
        zapClientAPI.users.setUserEnabled(API_KEY, contextId, userIdTemp, "true");
        listener.getLogger().println("User : " + username + " is now Enabled");

        // to make spidering and ajax spidering in authentication mod
        setUpForcedUser(listener, zapClientAPI, contextId, userIdTemp);

        return userIdTemp;
    }

    /**
     * set up forced user for the context and enable user, this help to make spidering and ajax spidering as authenticated user
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param contextId
     *            id of the created context
     * @return userId id of the newly setup user
     * @throws ClientApiException
     * @throws UnsupportedEncodingException
     */
    private void setUpForcedUser(BuildListener listener, ClientApi zapClientAPI, String contextid, String userid) throws ClientApiException, UnsupportedEncodingException {
        /*
         * @class org.zaproxy.clientapi.gen.ForcedUser
         * 
         * @method setForcedUser
         * 
         * @param String apikey
         * 
         * @param String contextid
         * 
         * @param String userid
         * 
         * @throws ClientApiException
         */
        zapClientAPI.forcedUser.setForcedUser(API_KEY, contextid, userid);

        /*
         * @class org.zaproxy.clientapi.gen.ForcedUser
         * 
         * @method setForcedUserModeEnabled
         * 
         * @param String apikey
         * 
         * @param boolean bool
         * 
         * @throws ClientApiException
         */
        zapClientAPI.forcedUser.setForcedUserModeEnabled(API_KEY, true);

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
    private void setUpAuthentication(BuildListener listener, ClientApi zapClientAPI, String loginURL, String username, String password, String loggedInIndicator, String extraPostData, String authMethod, String usernameParameter, String passwordParameter, String scriptName, String protectedPages) throws ClientApiException, UnsupportedEncodingException {

        // setup context
        // this.contextId=setUpContext(listener,url,zapClientAPI);

        // set up authentication method
        if (authMethod.equals(FORM_BASED)) setUpFormBasedAuth(listener, zapClientAPI, contextId, loginURL, loggedInIndicator, extraPostData, usernameParameter, passwordParameter);
        else if (authMethod.equals(SCRIPT_BASED)) setUpScriptBasedAuth(listener, zapClientAPI, contextId, loginURL, loggedInIndicator, extraPostData, scriptName, protectedPages);

        // set up user
        this.userId = setUpUser(listener, zapClientAPI, username, password, contextId);
    }

    /**
     * Search for all links and pages on the URL and raised passives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param url
     *            the url to investigate
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void spiderURL(BuildListener listener, ClientApi zapClientAPI, final String url) throws ClientApiException, InterruptedException {
        // TODO More Testing
        if (getSpiderScanURL()) {
            loggerMessage(listener, "authMode = [ {0} ]", String.valueOf(this.authMode));
            loggerMessage(listener, "maxChildren = [ {0} ]", String.valueOf(this.spiderScanMaxChildrenToCrawl));
            loggerMessage(listener, "recurse = [ {0} ]", String.valueOf(this.spiderScanRecurse));
            loggerMessage(listener, "subtreeOnly = [ {0} ]", String.valueOf(this.spiderScanSubtreeOnly));
            if (!authMode) {
                loggerMessage(listener, "contextName = [ {0} ]", String.valueOf(this.evaluatedContextName));
                loggerMessage(listener, "Spider the site [ {0} ]", this.evaluatedTargetURL);
                /*
                 * @class org.zaproxy.clientapi.gen.Spider
                 * 
                 * @method scan
                 * 
                 * @param String apikey
                 * 
                 * @param String url the starting point/seed of the spider (might be null or empty if the context already has a URL to start)
                 * 
                 * @param String maxchildren a number (0 default is no maximum) or empty string
                 * 
                 * @param String recurse true/false or empty string, default is true
                 * 
                 * @param String contextname the name of the context (if empty string, it's not spidering a context)
                 * 
                 * @param String true/false or subtreeonly empty string (default is false, which is to not limit to a subtree)
                 * 
                 * @throws ClientApiException
                 */
                zapClientAPI.spider.scan(API_KEY, url, String.valueOf(this.spiderScanMaxChildrenToCrawl), String.valueOf(this.spiderScanRecurse), this.evaluatedContextName, String.valueOf(this.spiderScanSubtreeOnly));
            }
            else if (authMode) {
                loggerMessage(listener, "this.contextId = [ {0} ]", String.valueOf(this.contextId));
                loggerMessage(listener, "this.userId = [ {0} ]", String.valueOf(this.userId));
                loggerMessage(listener, "Spider the site [ {0} ] as user [ {1} ]", this.evaluatedTargetURL, this.username);
                /*
                 * @class org.zaproxy.clientapi.gen.Spider
                 * 
                 * @method scanAsUser
                 * 
                 * @param String String apikey
                 * 
                 * @param String contextid the id of the context (if empty string, it's not spidering a context)
                 * 
                 * @param String userid
                 * 
                 * @param String url the starting point/seed of the spider (might be null or empty if the context already has a URL to start)
                 * 
                 * @param String maxchildren a number (0 default is no maximum) or empty string
                 * 
                 * @param String recurse true/false or empty string, default is true
                 * 
                 * @param String subtreeonly true/false or subtreeonly empty string (default is false, which is to not limit to a subtree)
                 * 
                 * @throws ClientApiException
                 */
                zapClientAPI.spider.scanAsUser(API_KEY, this.contextId, this.userId, url, String.valueOf(this.spiderScanMaxChildrenToCrawl), String.valueOf(this.spiderScanRecurse), String.valueOf(this.spiderScanSubtreeOnly));
            }
            // Wait for complete spidering (equal to 100)
            // Method signature : status(String scanId)
            // ASK ZAP DEV TEAM about STATUS BEING""

            /*
             * @class org.zaproxy.clientapi.gen.Spider
             * 
             * @method status
             * 
             * @param String scanid
             * 
             * @throws ClientApiException
             */
            while (statusToInt(zapClientAPI.spider.status("")) < 100) {
                listener.getLogger().println("Status spider = " + statusToInt(zapClientAPI.spider.status("")) + "%");
                listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
                Thread.sleep(1000);
            }
        }
        else loggerMessage(listener, "Skip spidering the site [ {0} ] ]", this.evaluatedTargetURL);
    }

    /**
     * Search for all links and pages on the URL and raised passives alerts
     *
     * @param url
     *            the url to investigate
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param contextId
     *            the id number of the contexte created for this scan
     * @param userId
     *            the id number of the user created for this scan
     * @throws ClientApiException
     * @throws InterruptedException
     */
    @Deprecated
    private void spiderURLAsUser(BuildListener listener, ClientApi zapClientAPI, final String url, String contextId, String userId) throws ClientApiException, InterruptedException {

        // TODO More Testing
        loggerMessage(listener, "this.authMode = [ {0} ]", String.valueOf(this.authMode));
        loggerMessage(listener, "this.contextId = [ {0} ]", String.valueOf(this.contextId));
        loggerMessage(listener, "this.userId = [ {0} ]", String.valueOf(this.userId));
        loggerMessage(listener, "maxChildren = [ {0} ]", String.valueOf(this.spiderScanMaxChildrenToCrawl));
        loggerMessage(listener, "recurse = [ {0} ]", String.valueOf(this.spiderScanRecurse));
        loggerMessage(listener, "recurse = [ {0} ]", String.valueOf(this.spiderScanSubtreeOnly));

        /*
         * @class org.zaproxy.clientapi.gen.Spider
         * 
         * @method scanAsUser
         * 
         * @param String String apikey
         * 
         * @param String contextid the id of the context (if empty string, it's not spidering a context)
         * 
         * @param String userid
         * 
         * @param String url the starting point/seed of the spider (might be null or empty if the context already has a URL to start)
         * 
         * @param String maxchildren a number (0 default is no maximum) or empty string
         * 
         * @param String recurse true/false or empty string, default is true
         * 
         * @param String subtreeonly true/false or subtreeonly empty string (default is false, which is to not limit to a subtree)
         * 
         * @throws ClientApiException
         */
        zapClientAPI.spider.scanAsUser(API_KEY, this.contextId, this.userId, url, String.valueOf(this.spiderScanMaxChildrenToCrawl), String.valueOf(this.spiderScanRecurse), String.valueOf(this.spiderScanSubtreeOnly));

        // Wait for complete spidering (equal to 100)
        // Method signature : status(String scanId)
        // TODO ASK ZAP DEV TEAM why scan id can be "" and what that means?
        /*
         * @class org.zaproxy.clientapi.gen.Spider
         * 
         * @method status
         * 
         * @param String scanid
         * 
         * @throws ClientApiException
         */
        while (statusToInt(zapClientAPI.spider.status("")) < 100) {
            listener.getLogger().println("Status spider = " + statusToInt(zapClientAPI.spider.status("")) + "%");
            listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
            Thread.sleep(1000);
        }
    }

    /**
     * Search for all links and pages on the URL and raised passives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param url
     *            the url to investigate
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void ajaxSpiderURL(BuildListener listener, ClientApi zapClientAPI, final String url) throws ClientApiException, InterruptedException {

        if (getAjaxSpiderURL()) {
            loggerMessage(listener, "Ajax Spider the site [ {0} ]", evaluatedTargetURL);
            // Method signature : scan(String apikey,String url,String inscope)
            // Parameters:apikey url inscope Throws:ClientApiException
            // ApiResponse org.zaproxy.clientapi.gen.AjaxSpider.scan(String apikey,
            // String url, String inscope) throws ClientApiException
            zapClientAPI.ajaxSpider.scan(API_KEY, url, String.valueOf(this.ajaxSpiderInScopeOnly));

            // Wait for complete spidering (equal to status complete)
            // Method signature : status(String scanId)
            while ("running".equalsIgnoreCase(statusToString(zapClientAPI.ajaxSpider.status()))) {
                listener.getLogger().println("Status spider = " + statusToString(zapClientAPI.ajaxSpider.status()));
                // ApiResponse org.zaproxy.clientapi.gen.Core.numberOfAlerts(String
                // baseurl) throws ClientApiException
                listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
                Thread.sleep(2500);
            }
        }
        else loggerMessage(listener, "Skip Ajax spidering the site [ {0} ]", evaluatedTargetURL);
    }

    /**
     * Scan all pages found at url and raised actives alerts
     *
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param url
     *            the url to scan
     * @throws ClientApiException
     * @throws InterruptedException
     */
    private void scanURL(BuildListener listener, ClientApi zapClientAPI, final String url) throws ClientApiException, InterruptedException {
        if (getActiveScanURL()) {
            // Use a default policy if activeScanPolicy is null or empty
            if (activeScanPolicy == null || activeScanPolicy.isEmpty()) listener.getLogger().println("Scan url [" + url + "] with the policy by default");
            else listener.getLogger().println("Scan url [" + url + "] with the following policy [" + activeScanPolicy + "]");

            if (!authMode) {
                loggerMessage(listener, "Scan the site [ {0} ]", evaluatedTargetURL);

                /*
                 * @class org.zaproxy.clientapi.gen.Ascan
                 * 
                 * @method scan
                 * 
                 * @param String String apikey
                 * 
                 * @param String url
                 * 
                 * @param String recurse true/false, default is true
                 * 
                 * @param String inscopeonly true/false, default is false, do not allow user change
                 * 
                 * @param String scanpolicyname depends on the policies that ZAP has, activeScanPolicy
                 * 
                 * @param String method can be any method GET/POST/PUT/DELETE..., default is null
                 * 
                 * @param String postdata the POST data a=b&c=d (or whatever format is used), default is null
                 * 
                 * @throws ClientApiException
                 * 
                 * @notes all of them can be null or empty strings, which is the same as not using them
                 * 
                 * @default values: true, false, default policy, GET, nothing
                 */
                zapClientAPI.ascan.scan(API_KEY, url, String.valueOf(this.activeScanRecurse), "false", this.activeScanPolicy, null, null);
            }
            else if (authMode) {
                loggerMessage(listener, "Spider the site [ {0} ] as user [ {1} ]", this.evaluatedTargetURL, this.username);
                // Method signature : scan(String apikey, String url, String recurse,
                // String inscopeonly, String scanpolicyname, String method, String
                // postdata)
                // Use a default policy if activeScanPolicy is null or empty
                // ApiResponse org.zaproxy.clientapi.gen.Ascan.scanAsUser(String apikey,
                // String url, String contextid, String userid, String recurse, String
                // scanpolicyname, String method, String postdata) throws
                // ClientApiException

                zapClientAPI.ascan.scanAsUser(API_KEY, url, this.contextId, this.userId, String.valueOf(this.activeScanRecurse), this.activeScanPolicy, null, null);
                // if user id is null then it would break, as that's to start the scan as a user
            }

            // Wait for complete scanning (equal to 100)
            // Method signature : status(String scanId)
            // ApiResponse org.zaproxy.clientapi.gen.Ascan.status(String scanid)
            // throws ClientApiException
            // : the status uses the ID of the scan which is returned when the scan is started
            // : if nothing is set it returns the status of the last scan
            while (statusToInt(zapClientAPI.ascan.status("")) < 100) {
                listener.getLogger().println("Status scan = " + statusToInt(zapClientAPI.ascan.status("")) + "%");
                // ApiResponse org.zaproxy.clientapi.gen.Core.numberOfAlerts(String
                // baseurl) throws ClientApiException
                // (2) is just the tab
                // 2:51:31 PM - thc202: numberOfAlerts allows to restrict by site/URL
                // 2:51:37 PM - thc202: if none is set it returns the number of all alerts
                // see http://localhost:8080/UI/core/view/numberOfAlerts/ it has a little description

                listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
                // ApiResponse org.zaproxy.clientapi.gen.Core.numberOfMessages(String baseurl)
                // throws ClientApiException
                listener.getLogger().println("Messages number = " + zapClientAPI.core.numberOfMessages("").toString(2));
                Thread.sleep(5000);
            }
        }
        else loggerMessage(listener, "Skip scanning the site [ {0} ]", evaluatedTargetURL);
    }

    /**
     * Scan all pages found at url and raised actives alerts
     *
     * @param url
     *            the url to scan
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param contextId
     *            the id number of the contexte created for this scan
     * @param userId
     *            the id number of the user created for this scan
     * @throws ClientApiException
     * @throws InterruptedException
     */
    @Deprecated
    private void scanURLAsUser(final String url, BuildListener listener, ClientApi zapClientAPI, String contextId, String userId) throws ClientApiException, InterruptedException {
        if (activeScanPolicy == null || activeScanPolicy.isEmpty()) listener.getLogger().println("Scan url [" + url + "] with the policy by default");
        else listener.getLogger().println("Scan url [" + url + "] with the following policy [" + activeScanPolicy + "]");

        // Method signature : scan(String apikey, String url, String recurse,
        // String inscopeonly, String scanpolicyname, String method, String
        // postdata)
        // Use a default policy if activeScanPolicy is null or empty
        // ApiResponse org.zaproxy.clientapi.gen.Ascan.scanAsUser(String apikey,
        // String url, String contextid, String userid, String recurse, String
        // scanpolicyname, String method, String postdata) throws
        // ClientApiException

        String recurse = "true";
        String scanpolicyname = activeScanPolicy;
        String method = null;
        String postdata = null;
        // TODO ASK ZAP TEAM
        zapClientAPI.ascan.scanAsUser(API_KEY, url, contextId, userId, recurse, scanpolicyname, method, postdata);
        // if user id is null then it would break, as that's to start the scan as a user

        // Wait for complete scanning (equal to 100)
        // Method signature : status(String scanId)

        // 2:50:25 PM - thc202: the status uses the ID of the scan which is returned when the scan is started
        // 2:50:33 PM - thc202: if nothing is set it returns the status of the last scan
        while (statusToInt(zapClientAPI.ascan.status("")) < 100) {
            listener.getLogger().println("Status scan = " + statusToInt(zapClientAPI.ascan.status("")) + "%");

            // 2:51:31 PM - thc202: numberOfAlerts allows to restrict by site/URL
            // 2:51:37 PM - thc202: if none is set it returns the number of all alerts
            // see http://localhost:8080/UI/core/view/numberOfAlerts/ it has a little description
            listener.getLogger().println("Alerts number = " + zapClientAPI.core.numberOfAlerts("").toString(2));
            listener.getLogger().println("Messages number = " + zapClientAPI.core.numberOfMessages("").toString(2));
            Thread.sleep(5000);
        }
    }

    /**
     * Stop ZAproxy if it has been previously started.
     *
     * @param zapClientAPI
     *            the client API to use ZAP API methods
     * @param listener
     *            the listener to display log during the job execution in jenkins
     * @throws ClientApiException
     */
    // private void stopZAP(ZAProxy zaproxy, ClientApi zapClientAPI,
    // BuildListener listener) throws ClientApiException {
    private void stopZAP(ClientApi zapClientAPI, BuildListener listener) throws ClientApiException {
        if (zapClientAPI != null) {
            listener.getLogger().println("Shutdown ZAProxy");
            // ApiResponse org.zaproxy.clientapi.gen.Core.shutdown(String apikey) throws ClientApiException
            zapClientAPI.core.shutdown(API_KEY);
        }
        else listener.getLogger().println("No shutdown of ZAP (zapClientAPI==null)");
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

        /**
         * Map where key is the report format represented by a String and value is a ZAPreport object allowing to generate a report with the corresponding format.
         */
        private Map<String, ZAPReport> mapFormatReport;

        /** Represents the build's workspace */
        private FilePath workspace;

        /**
         * In order to load the persisted global configuration, you have to call load() in the constructor.
         */
        public ZAPDriverDescriptorImpl() {
            mapFormatReport = ZAPReportCollection.getInstance().getMapFormatReport();
            load();
        }

        @Override
        public String getDisplayName() { return null; }

        public Map<String, ZAPReport> getMapFormatReport() { return mapFormatReport; }

        public List<String> getAllFormats() { return new ArrayList<String>(mapFormatReport.keySet()); }

        public void setWorkspace(FilePath ws) { this.workspace = ws; }

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
                    items.add(listFile.getName());
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
     * This class allows to launch a method on a remote machine (if there is, otherwise, on a local machine). The method launched is to wait the complete initialization of ZAProxy.
     **/
    private static class WaitZAPDriverInitCallable implements FileCallable<Void> {

        private static final long serialVersionUID = -313398999885177679L;

        private ZAPDriver zaproxy;
        private BuildListener listener;

        public WaitZAPDriverInitCallable(ZAPDriver zaproxy, BuildListener listener) {
            this.zaproxy = zaproxy;
            this.listener = listener;
        }

        @Override
        public Void invoke(File f, VirtualChannel channel) {
            zaproxy.waitForSuccessfulConnectionToZap(zaproxy.timeout, listener);
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

    private String contextId; /* Id of the newly created context */

    private String userId; /* Id of the newly created user */

    private String zapHost; /* Host configured when ZAPJ is used as proxy */

    public String getZapHost() { return zapHost; }

    public void setZapHost(String zapHost) { this.zapHost = zapHost; }

    /** Host configured when ZAProxy is used as proxy (it's derived from the one above) */
    private String evaluatedZapHost;

    public String getEvaluatedZapHost() { return evaluatedZapHost; }

    public void setEvaluatedZapHost(String evaluatedZapHost) { this.evaluatedZapHost = evaluatedZapHost; }

    private String zapPort; /* Port configured when ZAPJ is used as proxy */

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

    //private final boolean persistSession; /* Save session or not */

    //public boolean getPersistSession() { return persistSession; }

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

    public boolean getActiveScanRecurseL() { return activeScanRecurse; }

    private final String activeScanPolicy; /* The file policy to use for the scan. It contains only the policy name (without extension) */

    public String getActiveScanPolicy() { return activeScanPolicy; }
    /*****************************/

    /* Finalize Run */
    /* Finalize Run >> Generate Report(s) */
    /*****************************/
    private final boolean generateReports; /* Save reports or not */

    public boolean getGenerateReports() { return generateReports; }

    private final ArrayList<String> selectedReportFormats; /* List of chosen format for reports. ArrayList because it needs to be Serializable (whereas List is not Serializable) */

    public List<String> getSelectedReportFormats() { return selectedReportFormats; }

    private String reportFilename; /* Filename for ZAPJ reports. It can contain a relative path or environment variable */

    public String getReportFilename() { return reportFilename; }

    public void setReportFilename(String reportFilename) { this.reportFilename = reportFilename; }

    private String evaluatedReportFilename; /* Filename for ZAPJ reports. It can contain a relative path (it's derived from the one above) */
    // get and set of the new field which will contain the evaluated value of the report file name. So the environment variable will persist after each build

    public String getEvaluatedReportFilename() { return evaluatedReportFilename; }

    public void setEvaluatedReportFilename(String evaluatedReportFilename) { this.evaluatedReportFilename = evaluatedReportFilename; }
    /*****************************/

    /* Finalize Run >> Create JIRA Issue(s) */
    /*****************************/
    /* List of all parameters used for the ZAP add-on jiraIssueCreater */
    /* gets and sets the values from the credentials and base URI method call is from ZAPJBuilder */
    private final boolean createJiras; /* create JIRA'S or not */

    public boolean getcreateJiras() { return createJiras; }

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

    private final boolean alertHigh; /* select alert type high */

    public boolean getalertHigh() { return alertHigh; }

    private final boolean alertMedium; /* select alert type medium */

    public boolean getalertMedium() { return alertMedium; }

    private final boolean alertLow; /* select alert type low */

    public boolean getalertLow() { return alertLow; }

    private final boolean filterIssuesByResourceType; /* Filter issues by resource type */

    public boolean getfilterIssuesByResourceType() { return filterIssuesByResourceType; }
    /*****************************/
}
