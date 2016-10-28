   Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

# README for Apache Fortress Rest
 * Version 2.0.0-RC1
 * Apache Fortress Rest System Architecture Diagram
 ![Apache Fortress Rest System Architecture](images/fortress-rest-system-arch.png "Apache Fortress Rest System Architecture")

-------------------------------------------------------------------------------
## Table of Contents

 * Document Overview
 * Tips for first-time users.
 * SECTION 1. Prerequisites.
 * SECTION 2. Download & Install.
 * SECTION 3. Get the fortress.properties.
 * SECTION 4. Load Sample Security Policy.
 * SECTION 5. Deploy to Tomcat Server.
 * SECTION 6. Unit Test.
 * SECTION 7. Alternate testing procedures.

___________________________________________________________________________________
## Document Overview

This document contains instructions to download, build, and test operations using Apache Fortress Rest component.

___________________________________________________________________________________
##  Tips for first-time users

 * For a tutorial on how to use Apache Fortress check out the Fortress Core quickstart guides.
 * If you see **FORTRESS_CORE_HOME**, refer to the base package of [directory-fortress-core].
 * If you see **FORTRESS_REALM_HOME**, refer to the base package of [directory-fortress-realm].
 * If you see **FORTRESS_REST_HOME**, refer to this packages base folder.
 * If you see **TOMCAT_HOME**, refer to the location of that package's base folder.
 * Questions about this software package should be directed to its mailing list:
   * http://mail-archives.apache.org/mod_mbox/directory-fortress/


-------------------------------------------------------------------------------
## SECTION 1. Prerequisites

Minimum hardware requirements:
 * 2 Cores
 * 4GB RAM

Minimum software requirements:
 * Java SDK 7++
 * git
 * Apache Maven3++
 * Apache Tomcat7++
 * Apache Fortress Core **Download & Install** in **FORTRESS_CORE_HOME** package **README.md**.
 * Apache Fortress Core **Options for using Apache Fortress and LDAP server** in **FORTRESS_CORE_HOME** package **README.md**.
 * Apache Fortress Realm **Download & Install** in **FORTRESS_REALM_HOME** package **README.md**.

Everything else covered in steps that follow.  Tested on Debian, Centos & Windows systems.

-------------------------------------------------------------------------------
## SECTION 2. Download & Install

1. Build the source.

 a. from git:
 ```
 git clone --branch 2.0.0-RC1 https://git-wip-us.apache.org/repos/asf/directory-fortress-enmasse.git
 cd directory-fortress-enmasse
 mvn clean install
 ```

 b. or download package:

 ```
 wget http://www.apache.org/dist/directory/fortress/dist/2.0.0-RC1/fortress-rest-2.0.0-RC1-source-release.zip
 unzip fortress-rest-2.0.1-RC1.zip
 cd fortress-rest-2.0.1-RC1
 mvn clean install
 ```

2. Now build the javadoc:

 ```
 mvn javadoc:javadoc
 ```

 If using java 8, add this param to the pom.xml:
 ```
 <plugin>
    ...
    <artifactId>maven-javadoc-plugin</artifactId>
    <configuration>
        <additionalparam>-Xdoclint:none</additionalparam>
        ...
    </configuration>
 </plugin>
 ```

3. View the generated document here: [./target/site/apidocs/overview-summary.html](./target/site/apidocs/overview-summary.html).

___________________________________________________________________________________
## SECTION 3. Get the fortress.properties

These contain the coordinates to the target LDAP server.

1. Copy the **fortress.properties**, created during **FORTRESS_CORE_HOME** **README.md**, to this package's resource folder.

 ```
 cp $FORTRESS_CORE_HOME/config/fortress.properties $FORTRESS_REST_HOME/src/main/resources
 ```

2. Verify they match your target LDAP server.
 ```
 # This param tells fortress what type of ldap server in use:
 ldap.server.type=apacheds

 # ldap host name
 host=localhost

 # if ApacheDS is listening on
 port=10389

 # If ApacheDS, these credentials are used for read/write to fortress DIT
 admin.user=uid=admin,ou=system
 admin.pw=secret

 # This is min/max settings for admin pool connections:
 min.admin.conn=1
 max.admin.conn=10

 # This node contains more fortress properties stored on behalf of connecting LDAP clients:
 config.realm=DEFAULT
 config.root=ou=Config,dc=example,dc=com

 # Used by application security components:
 perms.cached=true

 # Fortress uses a cache:
 ehcache.config.file=ehcache.xml

 # Default for pool reconnect flag is false:
 enable.pool.reconnect=true
 ```

___________________________________________________________________________________
## SECTION 4. Load Sample Security Policy

Run maven install with load file:
```
mvn install -Dload.file=./src/main/resources/FortressRestServerPolicy.xml
```

___________________________________________________________________________________
## SECTION 5. Deploy to Tomcat Server

1. If Tomcat has global security enabled you must add credentials to pom.xml to authenticate:

 ```
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
 ```

2. copy **FORTRESS_REALM_HOME** proxy jar to **TOMCAT_HOME**/lib/

 ```
 cp $FORTRESS_REALM_HOME/proxy/target/fortress-realm-proxy-[version].jar $TOMCAT_HOME/lib
 ```

3. Restart Tomcat server.

4. Enter maven command to deploy to Tomcat:
 ```
 mvn tomcat:deploy
 ```

5. To redeploy:
 ```
 mvn tomcat:redeploy
 ```

___________________________________________________________________________________
## SECTION 6. Unit Test

Run unit test:
 ```
 mvn test -Dtest=EmTest
 ```

 Test Notes:
 * The Fortress Rest application must be deployed and running within your servlet container before the unit tests will complete successfully.  If your app server
  is running on a separate machine, or using port other than 8080, adjust the settings accordingly in src/main/test/java/org/apache/directory/fortress/rest/EmTest.java
 * For learning and troubleshooting, it is recommended that you use an HTTP proxy program, like Axis' tpMon to intercept the HTTP/XML request/responses between Fortress rest client and server.
 * The tests depend on sample security policy being loaded.

___________________________________________________________________________________
## SECTION 7: Alternate testing procedures

1. Another way to test Fortress Rest is using the Fortress Core APIs which can be configured to communicate via HTTP/REST.
To enable Fortress Core test client to route requests through Fortress Rest server, add these properties to build.properties in **FORTRESS_CORE_HOME** root folder:

2. Add these credentials to build.properties file located in the directory-fortress-core root folder.  It contains the HTTP coordinates to your deployed Fortress Rest server:
 ```
 http.user=demouser4
 http.pw=password
 http.host=localhost
 http.port=8080
 ```

3. Add this to the same file.  It will override default fortress managers to route calls through REST interface:
 ```
 enable.mgr.impl.rest=true
 ```

4. Now run the **FORTRESS_CORE_HOME** mvn install to seed the new properties:
 ```
 mvn install
 ```

5. Now run the **FORTRESS_CORE_HOME** unit tests:
 ```
 mvn test -Dtest=FortressJUnitTest
 ```

 All operations should now route through Fortress Rest server.

___________________________________________________________________________________
#### END OF README