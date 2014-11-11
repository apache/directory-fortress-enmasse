#
#   Licensed to the Apache Software Foundation (ASF) under one
#   or more contributor license agreements.  See the NOTICE file
#   distributed with this work for additional information
#   regarding copyright ownership.  The ASF licenses this file
#   to you under the Apache License, Version 2.0 (the
#   "License"); you may not use this file except in compliance
#   with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing,
#   software distributed under the License is distributed on an
#   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#   KIND, either express or implied.  See the License for the
#   specific language governing permissions and limitations
#   under the License.
#
#
#
# Fortress slapd.conf default settings.
# Note: Directives that begin with '@' are substitution parms for Fortress' build.xml 'init-slapd' target.
___________________________________________________________________________________
###################################################################################
README for Fortress EnMasse Web Application Installation
RC29 (BETA RELEASE CANDIDATE)
Last updated: August 29, 2013
___________________________________________________________________________________
###################################################################################
# Prerequisites
###################################################################################
1. Internet access to retrieve dependencies from online Maven repo.

NOTE: The EnMasse maven may run without connection to Internet iff:
- The binary dependencies are already present in M2_HOME

2. Java SDK Version 7 or beyond installed to target environment
3. Maven 3 installed to target environment
4. Fortress/OpenLDAP are installed to target system.
___________________________________________________________________________________
###################################################################################
# Important Notes about EnMasse Web Application
###################################################################################

1. EnMasse is released as Open Source and available for unrestricted use via BSD 3 clause license. (see LICENSE.txt)
  - EnMasse dependencies are Open Source also.

2. This web app was tested using Apache Tomcat 7 but would work inside any current Java Servlet container (with changes to deploy procedure)

3. Maven 'install' target in this package builds EnMasse war file which deploys to Java EE servlet container.

4. This document includes instructions to Compile, Deploy, run Javadoc and Test the EnMasse Web application using Apache Tomcat.

5. Security Measures implemented within this application include:

  - Java EE Security - Confidentiality, Authentication, Session Management
    - requires HTTP Basic Auth header exchange to pass credentials used for security checks.

  - Spring Security - Role-Based Access Control Interceptor
    - Service-level Authorization uses Spring Security.
    - To find out what Roles required to which Services, view the Spring annotations inside this file:
        enmasse-dist-[version]/src//main/java/org/openldap/enmasse/FortressServiceImpl.java

  - Fortress Sentry - Java EE security plugin for Identity, Coarse-grained Authorization, and Audit Trail

  - Passwords in Config Files - Encrypted using jasypt.

  - EnMasse - Identity, Administrative, Compliance and Review services.

  - OpenLDAP - Password Hashing, Policies.
___________________________________________________________________________________
###################################################################################
# SECTION 1:  Prerequisites for use of EnMasse Web Application
###################################################################################

Before you can successfully complete the steps to install and run EnMasse, the following steps must be completed:

1. Internet access from your target machine to Maven 2 online repos.

2. Maven 3 installed to target:
http://maven.apache.org/download.html
http://www.sonatype.com/books/mvnref-book/reference/installation-sect-maven-install.html

3. Java SDK Version 7 or beyond installed:
http://www.oracle.com/technetwork/java/javase/downloads/index.html

4. Fortress/OpenLDAP QUICKSTART installed:
instructions: http://www.joshuatreesoftware.us/iamfortress/guides/README-QUICKSTART.html
binaries: https://iamfortress.org/projects

5. Tomcat 7 installed:
http://tomcat.apache.org

6. Fortress Sentry package (a.k.a Realm) installed:
instructions: http://www.jts.us/iamfortress/javadocs/api-sentry/org/openldap/sentry/tomcat/package-summary.html
binaries: http://iamfortress.org/download

Note: There is a complete EnMasse demo that handles these prereqs for you located here:
http://iamfortress.org/EnMasse

_________________________________________________________________________________
###################################################################################
# SECTION 2:  Instructions for EnMasse installation using distribution package
###################################################################################

1. Retrieve Fortress EnMasse source code bundle either from iamfortress.org or OpenLDAP.org.

2. Extract contents of openldap-fortress-enmasse.tar.gz to target env.
___________________________________________________________________________________
###################################################################################
# SECTION 3:  Instructions to build EnMasse Web archive file
###################################################################################

1. Open a command prompt on target machine in the root folder of the enmasse-dist package

2. Set java home:
>export JAVA_HOME=/opt/jdk1.7.0_10

3. Set maven home:
>export M2_HOME=/usr/share/maven

4. Run maven install:
>mvn install

###################################################################################
# SECTION 4:  Instructions to Deploy EnMasse Web application to Tomcat
###################################################################################

1. Enable Maven to communicate with Tomcat using settings.xml file.

note: a typical location for this maven configuration file is: ~/.m2/settings.xml

Add to file:

<server>
	<id>local-tomcat</id>
      <username>tcmanager</username>
      <password>m@nager123</password>
</server>

note: If you followed the installation steps of Fortress QUICKSTART your Tomcat Manager creds would be as above.

2. Enter maven command to deploy to Tomcat:
>mvn tomcat:deploy

3. To redeploy:
>mvn tomcat:redeploy
___________________________________________________________________________________
###################################################################################
# SECTION 5:  Instructions to test EnMasse Web application
###################################################################################

1. Run maven test
>mvn test

note1: the EnMasse application must be deployed and running within your servlet container before the unit tests will complete successfully.  If your EnMasse server
 is running on a separate machine, or using port other than 8080, adjust the settings accordingly in EmTest Java module.
note2:  For learning and troubleshooting, it is recommended that you use an HTTP proxy program, like Axis' tpMon to intercept the HTTP/XML request/responses between EnMasse client and server.
note3:  The tests depend on user, 'demoUser4', already provisioned into LDAP assigned necessary role, 'EmSuperUser'.  demoUser4 is created during Fortress' 'init-slapd' Ant target.
note4:  If for any reason these tests should not be run during maven processing, adjust the following setting in project's pom.xml (set to 'true'):

    <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>2.12</version>
        <configuration>
            <skipTests>true</skipTests>
        </configuration>
    </plugin>


2. Another way to test EnMasse is using the Fortress APIs which can be configured as a proxy for EnMasse.  To enable Fortress client to route
API requests through EnMasse server, add these properties to fortress.properties in your Fortress client's /config folder:

# These credentials are used for accessing EnMasse:
http.user=demouser4
http.pw=gX9JbCTxJW5RiH+otQEX0Ja0RIAoPBQf   (note this password was encrypted using the Fortress 'encrypt' target in build.xml)
http.host=localhost
http.port=80

# These will override default and enable client to call REST implementations:
reviewmgr.implementation=org.apache.directory.fortress.core.rest.ReviewMgrRestImpl
adminmgr.implementation=org.apache.directory.fortress.core.rest.AdminMgrRestImpl
accessmgr.implementation=org.apache.directory.fortress.core.rest.AccessMgrRestImpl
delegated.adminmgr.implementation=org.apache.directory.fortress.core.rest.DelegatedAdminMgrRestImpl
delegated.reviewmgr.implementation=org.apache.directory.fortress.core.rest.DelegatedReviewMgrRestImpl
policymgr.implementation=org.apache.directory.fortress.core.rest.PswdPolicyMgrRestImpl
delegated.accessmgr.implementation=org.apache.directory.fortress.core.rest.DelegatedAccessMgrRestImpl
auditmgr.implementation=org.apache.directory.fortress.core.rest.AuditMgrRestImpl
configmgr.implementation=org.apache.directory.fortress.core.rest.ConfigMgrRestImpl

___________________________________________________________________________________
###################################################################################
# SECTION 6:  Instructions to create EnMasse javadoc (optional)
###################################################################################

The service level documentation provides descriptions for each of the EnMasse services + required and optional parameters for service invocations.

1. Enter the following:

$ mvn javadoc:javadoc

2. View the document output here:

openldap-fortress-enmasse/target/site/apidocs

3. To view Service-level documentation, go here:

openldap-fortress-enmasse/target/site/apidocs/org/openldap/enmasse/FortressServiceImpl.html