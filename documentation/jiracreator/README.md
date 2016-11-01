<a href='https://github.com/JordanGS/zaproxy-plugin/tree/development#table-of-contents-'><div align="right">Home</div></a>

<b>WARNING</b>: JIRA functionality requires an add-on <b>NOT</b> bundled with ZAP, nor available in the marketplace.

<b>USE AT YOUR OWN RISK AND DISCRETION</b>.

JIRA Creator: Jenkins Config
============

### Jenkins ![Image of Right Arrow](../images/arrow_right.png) Manage Jenkins ![Image of Right Arrow](../images/arrow_right.png) Configure System

`http://localhost:8080/configure`

![Image of JIRA Creator](../images/JIRA_ADMIN.png)

Required ONLY if you are planning create JIRA issues.

<hr />

JIRA Creator: Job Configuration
============

![Image of JIRA Creator Job Config](../images/JIRA_JOB_CONFIG.png)

<b>Required:</b> Set the JIRA Base URL, JIRA Username and JIRA Password as shown above.

##### 1. Project Key

##### 2. Assignee 

##### 3. Export Alerts

- Issues can be created depending on the alert level of each issue.
- A user can choose to export alerts as JIRA's depending on their severity.
	- High
	- Medium
	- Low
	- Informational
- <b>Notice</b>: At least one alert level has to be checked or else the plugin will fail.

##### 4. Filter Issue URL's by Resource Type 

- Filter issue URLS by resource type is an optional feature which can be used to categorize the urls by resource type.
	- e.g. css, html, js, jsp etc.

<a href='https://github.com/JordanGS/zaproxy-plugin/tree/development#table-of-contents-'><div align="right">Home</div></a>
