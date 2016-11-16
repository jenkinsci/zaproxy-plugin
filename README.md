
<a href='https://jenkins.ci.cloudbees.com/job/plugins/job/zaproxy-plugin/'><img src='https://jenkins.ci.cloudbees.com/buildStatus/icon?job=plugins/zaproxy-plugin'></a>

# Deprecated

This plugin has been removed from the Jenkins Plugin Center, it is not available for new downloads but will be available for existing users.
 
Archived versions of this plugin remain available for [download](http://archives.jenkins-ci.org/plugins/zaproxy/).
 
Due to data incompatibility, the plugin will no longer be distributed. Please migrate to the [Official OWASP Zed Attack Proxy Jenkins Plugin](https://wiki.jenkins-ci.org/display/JENKINS/zap+plugin).

# zaproxy-plugin
It's a Jenkins plugin that allows to start and execute the OWASP ZAP security tool (https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project).
With this plugin, you can spider and scan a target URL, save alerts security reports in all available formats in ZAProxy (xml, html, json) and also load and save ZAP sessions.

This plugin uses an external plugin to install ZAProxy on the machine with Jenkins (like Custom Tools Plugin) or ZAProxy must be already install before run builds.

For more informations, visit https://wiki.jenkins-ci.org/display/JENKINS/ZAProxy+Plugin.