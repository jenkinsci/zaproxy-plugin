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
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

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

        listener.getLogger().println("------- START Replace environment variables -------");

        /* Replaces the environment variables with the corresponding values */
        String zapHost = zaproxy.getZapHost();
        if (zapHost == null || zapHost.isEmpty()) throw new IllegalArgumentException("ZAP Host is missing");
        String zapPort = zaproxy.getZapPort();
        if (zapPort == null || zapPort.isEmpty()) throw new IllegalArgumentException("ZAP Port is missing");
        String zapSettingsDir = zaproxy.getZapSettingsDir();
        String contextName = zaproxy.getContextName();
        String includedURL = zaproxy.getIncludedURL();
        String excludedURL = zaproxy.getExcludedURL();
        String targetURL = zaproxy.getTargetURL();
        String reportName = zaproxy.getReportFilename();
        String sessionFilename = zaproxy.getSessionFilename();
        ArrayList<ZAPCmdLine> cmdLinesZap = new ArrayList<ZAPCmdLine>(zaproxy.getCmdLinesZAP().size());

        try {
            zapHost = applyMacro(build, listener, zapHost);
            zapPort = applyMacro(build, listener, zapPort);
            zapSettingsDir = applyMacro(build, listener, zapSettingsDir);
            contextName = applyMacro(build, listener, contextName);
            includedURL = applyMacro(build, listener, includedURL);
            excludedURL = applyMacro(build, listener, excludedURL);
            targetURL = applyMacro(build, listener, targetURL);
            reportName = applyMacro(build, listener, reportName);
            sessionFilename = applyMacro(build, listener, sessionFilename);
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
        zaproxy.setEvaluatedContextName(contextName);
        zaproxy.setEvaluatedIncludedURL(includedURL);
        zaproxy.setEvaluatedExcludedURL(excludedURL);
        zaproxy.setEvaluatedTargetURL(targetURL);
        zaproxy.setEvaluatedReportFilename(reportName);
        zaproxy.setEvaluatedSessionFilename(sessionFilename);
        zaproxy.setEvaluatedCmdLinesZap(cmdLinesZap);

        listener.getLogger().println("ZapHost : " + zapHost);
        listener.getLogger().println("ZapPort : " + zapPort);
        listener.getLogger().println("");
        listener.getLogger().println("zapSettingsDir : " + zapSettingsDir);
        listener.getLogger().println("");
        listener.getLogger().println("ContextName : " + contextName);
        listener.getLogger().println("IncludedURL : " + includedURL);
        listener.getLogger().println("ExcludedURL : " + excludedURL);
        listener.getLogger().println("");
        listener.getLogger().println("TargetURL : " + targetURL);
        listener.getLogger().println("");
        listener.getLogger().println("ReportName : " + reportName);
        listener.getLogger().println("");
        listener.getLogger().println("SessionFilename : " + sessionFilename);
        listener.getLogger().println("");
        listener.getLogger().println("CmdLInesZap : " + cmdLinesZap);

        // ArrayList<ZAPCmdLine> cmdLinesZap= new ArrayList<ZAPCmdLine>(zaproxy.getCmdLinesZAP().size());

        listener.getLogger().println("------- END Replace environment variables -------");

        if (startZAPFirst) {
            listener.getLogger().println("------- START Prebuild -------");

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
            listener.getLogger().println("------- END Prebuild -------");
        }
        return true;
    }

    /** Method called when the build is launching */
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {

        listener.getLogger().println("Perform ZAProxy");

        if (!startZAPFirst) try {
            proc = zaproxy.startZAP(build, listener, launcher);
        }
        catch (Exception e) {
            e.printStackTrace();
            listener.error(ExceptionUtils.getStackTrace(e));
            return false;
        }

        boolean res;
        try {
            res = build.getWorkspace().act(new ZAPDriverCallable(this.zaproxy, listener));
            proc.joinWithTimeout(60L, TimeUnit.MINUTES, listener);

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
            listener.getLogger().println("Failed to apply macro " + macro);
            listener.error(ExceptionUtils.getStackTrace(e));
        }
        return macro;
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
        private ZAPDriver zaproxy;
        private BuildListener listener;

        public ZAPDriverCallable(ZAPDriver zaproxy, BuildListener listener) {
            this.zaproxy = zaproxy;
            this.listener = listener;
        }

        @Override
        public Boolean invoke(File f, VirtualChannel channel) { return zaproxy.executeZAP(new FilePath(f), listener); }

        @Override
        public void checkRoles(RoleChecker checker) throws SecurityException { /* N/A */ }
    }
}
