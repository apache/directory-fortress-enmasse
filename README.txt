Copyright © 2011-2012. Joshua Tree Software, LLC.  All Rights Reserved.
___________________________________________________________________________________
###################################################################################
README for JoshuaTree EnMasse Web Application
RC18 (Beta RELEASE CANDIDATE)
Last updated: December 2, 2012
___________________________________________________________________________________
###################################################################################
# Prerequisites for use
###################################################################################

1. Internet access to retrieve EnMasse binary dependencies using Maven.

2. Java SDK Version 6 or beyond installed to target environment.

3. Fortress and OpenLDAP installed, configured and available on your network.
To get Fortress QUICKSTART packages, go to this link: https://iamfortress.org/projects
  - Fortress QUICKSTART packages containing Fortress/Symas OpenLDAP binary distributions.
  - EnMasse QUICKSTART packages containing pre-loaded Apache Tomcat 7.0.27 server distributions.

4. Tomcat 6 and beyond installed to target environment.

5. Fortress Realm configured for Tomcat
___________________________________________________________________________________
###################################################################################
# Guidelines & Tips for first-time users
###################################################################################

1. In the document that follows, when you read "[version]" substitute with current info.
  For example - if the downloaded package version is 1.0 change enmasse-[version] to enmasse-1.0

2. The source code for this project is located under enmasse-[version]/src folder.

3. For EnMasse Services-level documentation, jump to SECTION 6.
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
        ENMASSE_HOME/src//main/java/com/jts/enmasse/FortressServiceImpl.java

  - Fortress Sentry - Java EE security plugin for Identity, Coarse-grained Authorization, and Audit Trail

  - Passwords in Config Files - Encrypted using jasypt.

  - EnMasse - Identity, Administrative, Compliance and Review services.

  - OpenLDAP - Password Hashing, Policies.
___________________________________________________________________________________
###################################################################################
# SECTION 1:  Prerequisites for use
###################################################################################

1. Java SDK Version 6 or beyond installed to target environment

2. Apache Ant 1.8 or beyond installed to target environment

3. Apache Maven installed on target machine.  This is used to manage the EnMasse dependencies and build the .war.

4. Fortress and OpenLDAP installed, configured and available on your network.
To get Fortress QUICKSTART packages, go to this link: https://iamfortress.org/projects
  - Fortress QUICKSTART packages containing Fortress/Symas OpenLDAP binary distributions.
  - EnMasse QUICKSTART packages containing pre-loaded Apache Tomcat 7.0.27 server distributions.

5. Apache Tomcat server on local machine.  (this is included in enmasse-distro-[version])

6. JoshuaTree Sentry package (a.k.a Realm) configured for Tomcat security.
This is used to provide Java EE security for applications running in Tomcat application server.
Sentry can be obtained in binary bundles from JoshuaTree, Or, in source form on OpenLDAP GIT repo:
http://www.openldap.org/devel/gitweb.cgi?p=openldap-fortress-realm.git;a=summary.  Use latest version, RC16.

7. JoshuaTree EnMasse source code package.  (included in enmasse-distro)
__________________________________________________________________________________
###################################################################################
# SECTION 2:  Instructions for EnMasse installation
###################################################################################

1. Extract contents of enmasse-distro-[version].zip to target env.

Note:  In the document that follows, when you read "ENMASSE_HOME" substitute the location the package was extracted to on this step.

2. Enable permission for the shell scripts to execute.  From root folder of ENMASSE_HOME package, enter the following
command from a command prompt:
>chmod a+x -Rf *.sh

3. Set Tomcat's JAVA_HOME environment property inside enmasse-distro-[version]/apache-tomcat-7.0.27/bin/catalina.sh:

>export JAVA_HOME=/opt/jdk1.6.0_27

4. Set Java Sentry realmClasspath in Tomcat's enmasse-distro-[version]/apache-tomcat-7.0.27/conf/server.xml.

Set the absolute path to match that of your system's:

realmClasspath="/home/smckinn/tmp/enmasse/2/enmasse-distro-[version]/apache-tomcat-7.0.27/fortressSentryDist-[version]/conf:/home/smckinn/tmp/enmasse/2/enmasse-distro-[version]/apache-tomcat-7.0.27/fortressSentryDist-[version]/lib/fortressSentry-[version].jar"/>

5. open a shell prompt here: enmasse-distro-[version]/apache-tomcat-7.0.27/bin and execute this command:

>./startup.sh

6. tail the logs (from same prompt tomcat was started from):

>tail -f -n10000 ../logs/catalina.out

7. ensure there are not any errors in Tomcat's logs after startup.
___________________________________________________________________________________
###################################################################################
# SECTION 3:  Instructions to build EnMasse Web archive file
###################################################################################

1. open a command prompt on target machine in the root folder of the EnMasse source package, ./enmasse-distro-[version]/

2. set java home:
>export JAVA_HOME=/opt/jdk1.6.0_27/

3. set maven home:
>export M2_HOME=/usr/share/maven2

4. run maven install:
>mvn install

###################################################################################
# SECTION 4:  Instructions to Deploy to Tomcat
###################################################################################

1. Enable Maven to communicate with Tomcat:

Add to settings.xml:

<server>
	<id>local-tomcat</id>
	<username>admin</username>
	<password>password</password>
</server>

where admin and password are the credentials to access Tomcat Manager.

2. enter maven command to deploy to Tomcat:
>mvn tomcat:deploy
___________________________________________________________________________________
___________________________________________________________________________________
###################################################################################
# SECTION 5:  Instructions to test EnMasse
###################################################################################

1. run maven test
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
reviewmgr.implementation=com.jts.fortress.rest.ReviewMgrRestImpl
adminmgr.implementation=com.jts.fortress.rest.AdminMgrRestImpl
accessmgr.implementation=com.jts.fortress.rest.AccessMgrRestImpl
delegated.adminmgr.implementation=com.jts.fortress.rest.DelegatedAdminMgrRestImpl
delegated.reviewmgr.implementation=com.jts.fortress.rest.DelegatedReviewMgrRestImpl
policymgr.implementation=com.jts.fortress.rest.PswdPolicyMgrRestImpl
delegated.accessmgr.implementation=com.jts.fortress.rest.DelegatedAccessMgrRestImpl
auditmgr.implementation=com.jts.fortress.rest.AuditMgrRestImpl
configmgr.implementation=com.jts.fortress.rest.ConfigMgrRestImpl

___________________________________________________________________________________
###################################################################################
# SECTION 6:  Instructions to create EnMasse javadoc (optional)
###################################################################################

1. Enter the following:

$ mvn javadoc:javadoc

2. View the document output here:

ENMASSE_HOME/target/site/apidocs

3. To view Service-level documentation, go here:

ENMASSE_HOME/target/site/apidocs/com/jts/enmasse/FortressServiceImpl.html