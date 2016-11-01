<a href='https://github.com/JordanGS/zaproxy-plugin/tree/development#table-of-contents-'><div align="right">Home</div></a>

Export Report
=============

![Image of Export Report](../images/EXPORT_REPORT.png)

#### 1. Generate Reports

- Clear Workspace Reports
	- Delete all previously generated reports from the workspace before any new reports are generated. (.<b>html</b> <a href='http://www.w3schools.com/html/html_xhtml.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/html.png'></a>, .<b>xhtml</b> <a href='http://www.w3schools.com/html/html_xhtml.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/html.png'></a>, .<b>xml</b> <a href='http://www.w3schools.com/xml/default.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/xml.png'></a>, .<b>json</b> <a href='http://www.w3schools.com/js/js_json_intro.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/json.png'></a>)
	- Useful when used in conjunction with [Summary Display](../summarydisplay/README.md) and [HTML Publisher](../htmlpublisher/README.md)
- Filename
	- Specify a filename for the ZAP Report.
	- The file extension is not necessary.
	- The report will be saved into the <i>Jenkins Job's Workspace</i>
	- Example of a good filename: `JENKINS_ZAP_VULNERABILITY_REPORT_${BUILD_ID}`.

#### 2. Export Report
- Format: You can select multiple formats.
	- .<b>xhtml</b> <a href='http://www.w3schools.com/html/html_xhtml.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/html.png'></a>
	- .<b>xml</b> <a href='http://www.w3schools.com/xml/default.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/xml.png'></a>
	- .<b>json</b> <a href='http://www.w3schools.com/js/js_json_intro.asp'><img src='https://github.com/zaproxy/zap-extensions/blob/alpha/src/org/zaproxy/zap/extension/exportreport/resources/images/json.png'></a>

<hr />

Export Report: Source Details
=============

- Title
	- Provide a title for the report to be generated.
	- Example of a good title: `[BUILD #${BUILD_ID}] Vulnerability Report of ${NAME}`.

![Image of Export Report Source Details](../images/EXPORT_REPORT_SOURCE_DETAILS.png)

<hr />

Export Report: Alert Severity
=============

Include/Exclude Alerts by Severity.

![Image of Export Report Alert Severity](../images/EXPORT_REPORT_ALERT_SEVERITY.png)

<hr />

Export Report: Alert Details
=============

Include/Exclude Details of each Alert.

![Image of Export Report Alert Details](../images/EXPORT_REPORT_ALERT_DETAILS.png)

<a href='https://github.com/JordanGS/zaproxy-plugin/tree/development#table-of-contents-'><div align="right">Home</div></a>
