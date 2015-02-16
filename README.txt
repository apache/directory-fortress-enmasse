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
___________________________________________________________________________________
###################################################################################
README for Fortress Rest Application Installation
Last updated: February 16, 2015
___________________________________________________________________________________
###################################################################################
# SECTION 0.  Prerequisites for Fortress Rest installation and usage
###################################################################################
a. Internet access to retrieve source code from Apache Fortress Rest GIT and binary dependencies from online Maven repo.

b. Git installed to target machine.

c. Java SDK Version 7 or beyond installed to target machine.

d. Apache Maven 3 installed to target machine.

e. Fortress Core installed to target machine.
(as described in README.txt located in the Apache Fortress Core package)

f. Fortress Realm installed to target machine.
(as described in README.txt located in the Apache Fortress Realm package)

g. Fortress enabled LDAP server installed to target environment.
(as described in README.txt located in the Apache Fortress Core package)

h. Apache Tomcat 7 or greater installed to target environment and Realm enabled.
(as described in REALM_CONTEXT_SETUP.txt or REALM_HOST_SETUP.txt located in the Apache Fortress Realm package).
_________________________________________________________________________________
###################################################################################
# SECTION 1:  Instructions to clone source from Fortress Rest Git Repo:
###################################################################################
a. Clone the directory-fortress-enmasse from apache git repo:
# git clone https://git-wip-us.apache.org/repos/asf/directory-fortress-enmasse.git

b. Change directory to package home:
# cd directory-fortress-enmasse/
___________________________________________________________________________________
###################################################################################
# SECTION 2:  Instructions to build Fortress Rest
###################################################################################
a. Open a command prompt on target machine in the root folder of the directory-fortress-enmasse package

b. Set java home and maven home

c. Run maven install:
# mvn clean install -DskipTests

d. Build the javadoc:
# mvn javadoc:javadoc

f. To view Service-level documentation, point your web browser here:
file:///[directory-fortress-enmasse]/target/site/apidocs/org/apache/directory/fortress/rest/FortressServiceImpl.html

(where [directory-fortress-enmasse] is location of this source package)
___________________________________________________________________________________
###################################################################################
# SECTION 3:  Obtain the fortress.properties
###################################################################################
Copy the fortress.properties, created during Fortress Core setup, to this package's resource folder.

# cp [directory-fortress-core]/config/fortress.properties [directory-fortress-enmasse]/src/main/resources

Where [directory-fortress-core] is base folder of the fortress core source package and [directory-fortress-enmasse] is the current package's home folder.
___________________________________________________________________________________
###################################################################################
# SECTION 4:  Load Test Users
###################################################################################
Run maven install with load file:
# mvn install -Dload.file=./src/main/resources/FortressRestServerRoles.xml -DskipTests=true

###################################################################################
# SECTION 5:  Instructions to Deploy Fortress Rest application to Tomcat
###################################################################################
a. If Tomcat has global security enabled you must add credentials to pom.xml:

      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>tomcat-maven-plugin</artifactId>
        <version>${version.tomcat.maven.plugin}</version>
        <configuration>
            ...
          <!-- Warning the tomcat manager creds here are for deploying into a demo environment only. -->
          <username>tcmanager</username>
          <password>m@nager123</password>
        </configuration>
      </plugin>

b. Copy the Fortress Realm Proxy jar file to Tomcat's server/lib folder.
   Place the fortress-realm proxy jar, generated by the [directory-fortress-realm] package into Tomcat server's /lib folder.
   The proxy jar name is fortress-realm-proxy-[version].jar and located here: [directory-fortress-realm]/proxy/target.

Where [directory-fortress-realm] is base folder of the fortress realm source package.

c. Restart Tomcat server.

Note: REALM_CONTEXT_SETUP.txt and REALM_HOST_SETUP.txt, located in directory-fortress-realm package describes the Tomcat setup in more detail.

d. Enter maven command to deploy to Tomcat:
# mvn tomcat:deploy

e. To deploy:
# mvn tomcat:deploy

f. To redeploy:
# mvn tomcat:redeploy
___________________________________________________________________________________
###################################################################################
# SECTION 6:  Instructions to test Fortress Rest application
###################################################################################
Run maven test
# mvn verify -Dnoload

notes:
    - The Fortress Rest application must be deployed and running within your servlet container before the unit tests will complete successfully.  If your app server
      is running on a separate machine, or using port other than 8080, adjust the settings accordingly in src/main/test/java/org/apache/directory/fortress/rest/EmTest.java
    - For learning and troubleshooting, it is recommended that you use an HTTP proxy program, like Axis' tpMon to intercept the HTTP/XML request/responses between Fortress rest client and server.
    - The tests depend on user, 'demoUser4', already provisioned into LDAP assigned necessary role, during section 3.
    - If for any reason these tests should not be run during maven processing, adjust the following setting in project's pom.xml (set to 'true'):

    <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>2.12</version>
        <configuration>
            <skipTests>true</skipTests>
        </configuration>
    </plugin>

___________________________________________________________________________________
###################################################################################
# SECTION 7:  Alternate testing procedures
###################################################################################
Another way to test Fortress Rest is using the Fortress Core APIs which can be configured to communicate via HTTP/REST.
To enable Fortress Core test client to route requests through Fortres Rest server, add these properties to fortress.properties in your Fortress Core client's /config folder:

# These credentials are used for accessing EnMasse:
http.user=demouser4
http.pw=password
http.host=localhost
http.port=8080

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