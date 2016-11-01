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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.Launcher.LocalLauncher;
import hudson.Launcher.RemoteLauncher;
import hudson.Proc;
import hudson.Util;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.remoting.VirtualChannel;
import hudson.slaves.SlaveComputer;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import net.sf.json.JSONObject;

/*
 * @author Ludovic Roucoux
 * @author Johann Ollivier-Lapeyre
 * @author Thilina Madhusanka
 * @author Abdellah Azougarh
 * @author Goran Sarenkapa
 * @author Mostafa AbdelMoez
 * @author Tanguy de Lignières
 */

/**
 * The main class of the plugin. This class adds a build step in a Jenkins job that allows you to launch the ZAProxy security tool and get alerts reports from it.
 */
public class ZAPBuilder extends Builder {

    @DataBoundConstructor /* Fields in com/github/jenkinsci/zaproxyplugin/ZAPBuilder/config.jelly must match the parameter names in the "DataBoundConstructor" */
    public ZAPBuilder(boolean startZAPFirst, String zapHost, String zapPort, ZAPDriver zaproxy) {
        this.startZAPFirst = startZAPFirst;
        this.zaproxy = zaproxy;
        this.zapHost = zapHost;
        this.zapPort = zapPort;
        this.zaproxy.setStartZAPFirst(startZAPFirst);
        this.zaproxy.setZapHost(zapHost);
        this.zaproxy.setZapPort(zapPort);

        /* Call the set methods of ZAPDriver to set the values */
        this.zaproxy.setJiraBaseURL(ZAPBuilder.DESCRIPTOR.getJiraBaseURL());
        this.zaproxy.setJiraUsername(ZAPBuilder.DESCRIPTOR.getJiraUsername());
        this.zaproxy.setJiraPassword(ZAPBuilder.DESCRIPTOR.getJiraPassword());
    }

    /** To start ZAP as a pre-build step */
    private final boolean startZAPFirst;

    public boolean getStartZAPFirst() { return startZAPFirst; }

    /** The object to start and call ZAPDriver methods */
    private final ZAPDriver zaproxy;

    public ZAPDriver getZaproxy() { return zaproxy; }

    /** Host configured when ZAP is used as proxy */
    private final String zapHost;

    public String getZapHost() { return zapHost; }

    /** Port configured when ZAP is used as proxy */
    // private final int zapPort;
    private final String zapPort;

    public String getZapPort() { return zapPort; }

    private Proc proc;

    @Override /* Overridden for better type safety, not needed if plugin doesn't define any property on Descriptor */
    public ZAPBuilderDescriptorImpl getDescriptor() { return (ZAPBuilderDescriptorImpl) super.getDescriptor(); }

    /** Method launched before the build */
    @Override
    public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {

        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 0, "[{0}] START PRE-BUILD ENVIRONMENT VARIABLE REPLACEMENT", Utils.ZAP);

        /* Replaces the environment variables with the corresponding values */
        String zapHost = zaproxy.getZapHost();
        if (zapHost == null || zapHost.isEmpty()) throw new IllegalArgumentException("ZAP HOST IS MISSING");
        String zapPort = zaproxy.getZapPort();
        if (zapPort == null || zapPort.isEmpty()) throw new IllegalArgumentException("ZAP PORT IS MISSING");
        String zapSettingsDir = zaproxy.getZapSettingsDir();
        String sessionFilename = zaproxy.getSessionFilename();
        String contextName = zaproxy.getContextName();
        String includedURL = zaproxy.getIncludedURL();
        String excludedURL = zaproxy.getExcludedURL();
        String targetURL = zaproxy.getTargetURL();
        String reportName = zaproxy.getReportFilename();
        String reportTitle = zaproxy.getExportreportTitle();
        ArrayList<ZAPCmdLine> cmdLinesZap = new ArrayList<ZAPCmdLine>(zaproxy.getCmdLinesZAP().size());

        try {
            zapHost = applyMacro(build, listener, zapHost);
            zapPort = applyMacro(build, listener, zapPort);
            zapSettingsDir = applyMacro(build, listener, zapSettingsDir);
            sessionFilename = applyMacro(build, listener, sessionFilename);
            contextName = applyMacro(build, listener, contextName);
            includedURL = applyMacro(build, listener, includedURL);
            excludedURL = applyMacro(build, listener, excludedURL);
            targetURL = applyMacro(build, listener, targetURL);
            reportName = applyMacro(build, listener, reportName);
            reportTitle = applyMacro(build, listener, reportTitle);
            for (ZAPCmdLine cmdLineZap : zaproxy.getCmdLinesZAP())
                cmdLinesZap.add(new ZAPCmdLine(applyMacro(build, listener, cmdLineZap.getCmdLineOption()), applyMacro(build, listener, cmdLineZap.getCmdLineValue())));
        }
        catch (InterruptedException e1) {
            listener.error(ExceptionUtils.getStackTrace(e1));
        }

        /* Don't overwrite the filename containing the ENV VAR, evaluated value is saved in another filename */
        // the evaluated value is saved in an other file name
        zaproxy.setEvaluatedZapHost(zapHost);
        zaproxy.setEvaluatedZapPort(Integer.valueOf(zapPort));
        zaproxy.setEvaluatedZapSettingsDir(zapSettingsDir);
        zaproxy.setEvaluatedSessionFilename(sessionFilename);
        zaproxy.setEvaluatedContextName(contextName);
        zaproxy.setEvaluatedIncludedURL(includedURL);
        zaproxy.setEvaluatedExcludedURL(excludedURL);
        zaproxy.setEvaluatedTargetURL(targetURL);
        zaproxy.setEvaluatedReportFilename(reportName);
        zaproxy.setEvaluatedExportreportTitle(reportTitle);
        zaproxy.setEvaluatedCmdLinesZap(cmdLinesZap);

        Utils.loggerMessage(listener, 1, "HOST = [ {0} ]", zapHost);
        Utils.loggerMessage(listener, 1, "PORT = [ {0} ]", zapPort);
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 1, "ZAP SETTINGS DIRECTORY = [ {0} ]", zapSettingsDir);
        Utils.loggerMessage(listener, 1, "SESSION FILENAME = [ {0} ]", sessionFilename);
        Utils.loggerMessage(listener, 1, "CONTEXT NAME = [ {0} ]", contextName);
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 1, "INCLUDE IN CONTEXT = [ {0} ]", includedURL.trim().replace("\n", ", "));
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 1, "EXCLUDE FROM CONTEXT = [ {0} ]", excludedURL.trim().replace("\n", ", "));
        Utils.lineBreak(listener);
        Utils.loggerMessage(listener, 1, "STARTING POINT (URL) = [ {0} ]", targetURL);
        Utils.loggerMessage(listener, 1, "REPORT FILENAME = [ {0} ]", reportName);
        Utils.loggerMessage(listener, 1, "REPORT TITLE = [ {0} ]", reportTitle);
        Utils.lineBreak(listener);
        // Utils.loggerMessage(listener, 1, "COMMAND LINE = [ {0} ] ", cmdLinesZap.toString().trim().substring(1, cmdLinesZap.toString().trim().length() - 1));
        Utils.loggerMessage(listener, 1, "COMMAND LINE = {0}", cmdLinesZap.toString().trim().substring(1, cmdLinesZap.toString().trim().length() - 1).replace(",", ""));

        if (cmdLinesZap.isEmpty()) Utils.lineBreak(listener);
        // MAYBE ADD environment variables for script param's
        // ArrayList<ZAPCmdLine> cmdLinesZap= new ArrayList<ZAPCmdLine>(zaproxy.getCmdLinesZAP().size());
        Utils.loggerMessage(listener, 0, "[{0}] END PRE-BUILD ENVIRONMENT VARIABLE REPLACEMENT", Utils.ZAP);
        Utils.lineBreak(listener);

        if (startZAPFirst) {
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] START PRE-BUILD STEP", Utils.ZAP);
            Utils.lineBreak(listener);

            try {
                Launcher launcher = null;
                Node node = build.getBuiltOn();

                /* Create launcher according to the build's location (Master or Slave) and the build's OS */
                if ("".equals(node.getNodeName())) launcher = new LocalLauncher(listener, build.getWorkspace().getChannel());
                else { /* Build on slave */
                    boolean isUnix;
                    if ("Unix".equals(((SlaveComputer) node.toComputer()).getOSDescription())) isUnix = true;
                    else isUnix = false;
                    launcher = new RemoteLauncher(listener, build.getWorkspace().getChannel(), isUnix);
                }
                proc = zaproxy.startZAP(build, listener, launcher);
            }
            catch (Exception e) {
                e.printStackTrace();
                listener.error(ExceptionUtils.getStackTrace(e));
                return false;
            }
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] END PRE-BUILD STEP", Utils.ZAP);
            Utils.lineBreak(listener);
        }
        return true;
    }

    /** Method called when the build is launching */
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
        if (!startZAPFirst) try {
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] START BUILD STEP", Utils.ZAP);
            Utils.lineBreak(listener);
            proc = zaproxy.startZAP(build, listener, launcher);
        }
        catch (Exception e) {
            e.printStackTrace();
            listener.error(ExceptionUtils.getStackTrace(e));
            return false;
        }

        boolean res;
        try {
            res = build.getWorkspace().act(new ZAPDriverCallable(listener, this.zaproxy));
            proc.joinWithTimeout(60L, TimeUnit.MINUTES, listener);
            Utils.lineBreak(listener);
            Utils.lineBreak(listener);
            Utils.loggerMessage(listener, 0, "[{0}] SHUTDOWN [ SUCCESSFUL ]", Utils.ZAP);
            Utils.lineBreak(listener);

            Utils.loggerMessage(listener, 0, "[{0}] SETTINGS DIR [ {1} ]", Utils.ZAP, this.zaproxy.getEvaluatedZapSettingsDir());
            Utils.loggerMessage(listener, 0, "[{0}] WORKSPACE [ {1} ]", Utils.ZAP, build.getWorkspace().getRemote());
            Utils.loggerMessage(listener, 0, "[{0}] LOG SEARCH...", Utils.ZAP);
            // copyPolicyFile(build.getWorkspace(), listener); // TODO maybe in future version
            
            // No workspace before the first build, so workspace is null
            FilePath ws = build.getWorkspace();
            if (ws != null) {
                File[] listFiles = {};
                try {
                    listFiles = ws.act(new LogCallable(this.zaproxy.getEvaluatedZapSettingsDir()));
                }
                catch (IOException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                catch (InterruptedException e) {
                    // No listener because it's not during a build but it's on the job config page
                    e.printStackTrace();
                }
                for (File listFile : listFiles) {
                    Utils.loggerMessage(listener, 1, "[ {0} ] LOG HAS BEEN FOUND", listFile.getAbsolutePath());
                    String stringForLogger = "Copy [" + listFile.getName() + "] to ";
                    stringForLogger = ws.act(new CopyFileCallable(listFile, build.getWorkspace().getRemote(), stringForLogger));
                    listener.getLogger().println(stringForLogger);
                }
            }
            
            Utils.lineBreak(listener);
        }
        catch (Exception e) {
            e.printStackTrace();
            listener.error(ExceptionUtils.getStackTrace(e));
            return false;
        }
        return res;
    }

    /**
     * Replace macro with environment variable if it exists
     *
     * @param build
     * @param listener
     * @param macro
     * @return
     * @throws InterruptedException
     */
    public static String applyMacro(AbstractBuild<?, ?> build, BuildListener listener, String macro) throws InterruptedException {
        try {
            EnvVars envVars = new EnvVars(Computer.currentComputer().getEnvironment());
            envVars.putAll(build.getEnvironment(listener));
            envVars.putAll(build.getBuildVariables());
            return Util.replaceMacro(macro, envVars);
        }
        catch (IOException e) {
            Utils.loggerMessage(listener, 0, "[{0}] ERROR, FAILED TO APPLY MACRO: {1}", Utils.ZAP, macro);
            listener.error(ExceptionUtils.getStackTrace(e));
        }
        return macro;
    }

    /**
     * Copy local policy file to slave in policies directory of ZAP default directory.
     * 
     * @param workspace the workspace of the build
     * @param listener
     * @throws IOException
     * @throws InterruptedException
     */
//    private void copyLogFiles(FilePath workspace, BuildListener listener, String data, String filename, String zapSettingsDir) throws IOException, InterruptedException {
        //if(zaproxy.getScanURL() && zaproxy.pathToLocalPolicy != null && !zaproxy.pathToLocalPolicy.isEmpty())
        //File logFile = new File(zapSettingsDir, "goran.txt");
        //String stringForLogger = "Copy [" + logFile.getAbsolutePath() + "] to ";

        //String data = FileUtils.readFileToString(logFile, (String)null);
        
//        Path pathLogDir = Paths.get(workspace.getRemote(), "logs", filename);
//        File f = pathLogDir.toFile();
//        String stringForLogger = "Copy [" + filename + "] to ";
//        stringForLogger = workspace.act(new CopyFileCallable(data, zapSettingsDir, f, stringForLogger));
//
//        listener.getLogger().println(stringForLogger);
//    }
    
    /**
     * Allows to copy local policy file to the default ZAP policies directory in slave.
     * 
     */
    private static class CopyFileCallable implements FileCallable<String> {
        private static final long serialVersionUID = -3375349701206827354L;
        private File sourceFile;
        private String destination;
        private String stringForLogger;
        
        public CopyFileCallable(File sourceFile, String destination, String stringForLogger) {
            this.sourceFile = sourceFile;
            this.destination = destination;
            this.stringForLogger = stringForLogger;
        }

        public String invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            String data = FileUtils.readFileToString(sourceFile, (String)null);
            String filename = sourceFile.getName();

            File destFile = new File(destination, filename);
            //File fileCopied = new File(fileCopiedDir, copyFilename);
                           
                FileUtils.writeStringToFile(destFile, data);
                stringForLogger += "[" + destFile.getAbsolutePath() + "]";
                return stringForLogger;
        }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException {
            // Nothing to do
        }
    }

    /**
     * Descriptor for {@link ZAPBuilder}. Used as a singleton. The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/com/github/jenkinsci/zaproxyplugin/ZAPBuilder/*.jelly</tt> for the actual HTML fragment for the configuration screen.
     */
    @Extension /* This indicates to Jenkins this is an implementation of an extension point. */
    public static final ZAPBuilderDescriptorImpl DESCRIPTOR = new ZAPBuilderDescriptorImpl();

    public static final class ZAPBuilderDescriptorImpl extends BuildStepDescriptor<Builder> {

        /* In order to load the persisted global configuration, you have to call load() in the constructor. */
        public ZAPBuilderDescriptorImpl() { load(); }

        /* Indicates that this builder can be used with all kinds of project types */
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) { return true; }

        /* This human readable name is used in the configuration screen. */
        @Override
        public String getDisplayName() { return "Execute ZAP"; }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            /* To persist global configuration information, set that to properties and call save(). */
            zapDefaultHost = formData.getString("zapDefaultHost");
            zapDefaultPort = formData.getString("zapDefaultPort");

            /* set the values from the global configuration for CREATE JIRA ISSUES */
            jiraBaseURL = formData.getString("jiraBaseURL");
            jiraUsername = formData.getString("jiraUsername");
            jiraPassword = formData.getString("jiraPassword");

            // ^Can also use req.bindJSON(this, formData);
            // (easier when there are many fields; need set* methods for this, like setUseFrench)

            save();
            return super.configure(req, formData);
        }

        /*
         * To persist global configuration information, simply store it in a field and call save().
         *
         * If you don't want fields to be persisted, use transient.
         */

        private String zapDefaultHost;

        public String getZapDefaultHost() { return zapDefaultHost; }

        private String zapDefaultPort;

        public String getZapDefaultPort() { return zapDefaultPort; }

        private String jiraBaseURL;

        public String getJiraBaseURL() { return jiraBaseURL; }

        private String jiraUsername;

        public String getJiraUsername() { return jiraUsername; }

        private String jiraPassword;

        public String getJiraPassword() { return jiraPassword; }
    }

    /**
     * Used to execute ZAP remotely.
     */
    private static class ZAPDriverCallable implements FileCallable<Boolean> {

        private static final long serialVersionUID = -313398999885177679L;
        private BuildListener listener;
        private ZAPDriver zaproxy;

        public ZAPDriverCallable(BuildListener listener, ZAPDriver zaproxy) {
            this.listener = listener;
            this.zaproxy = zaproxy;
        }

        @Override
        public Boolean invoke(File f, VirtualChannel channel) { return zaproxy.executeZAP(listener, new FilePath(f)); }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }

    /**
     * This class allows to search all ZAP authentication script files in the ZAP default dir of the remote machine (or local machine if there is no remote machine). It's used in the plugin configuration page to fill the list of authentication script files and choose one of them.
     */
    private static class LogCallable implements FileCallable<File[]> {

        private static final long serialVersionUID = 1328740269013881941L;

        private String zapSettingsDir;

        public LogCallable(String zapSettingsDir) { this.zapSettingsDir = zapSettingsDir; }

        @Override
        public File[] invoke(File f, VirtualChannel channel) {
            File[] listFiles = {};

            Path pathLogDir = Paths.get(zapSettingsDir);

            if (Files.isDirectory(pathLogDir)) {
                File zapAuthScriptsDir = pathLogDir.toFile();
                // create new filename filter (the filter returns true as all the extensions are accepted)
                FilenameFilter logFilter = new FilenameFilter() {

                    @Override
                    public boolean accept(File dir, String name) {
                        if (name.contains("zap.log")) return true;
                        return false;
                    }
                };

                // returns pathnames for files and directory
                listFiles = zapAuthScriptsDir.listFiles(logFilter);
            }
            return listFiles;
        }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }
}
