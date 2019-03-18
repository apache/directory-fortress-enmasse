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

# README-QUICKSTART for Apache Fortress Rest
 * version 2.0.3

-------------------------------------------------------------------------------
## Table of Contents

 * Document Overview
 * SECTION 1. Prerequisites
 * SECTION 2. Configure Tomcat and Deploy Fortress Rest
 * SECTION 3. Load Sample Security Policy
 * SECTION 4. Test
 * SECTION 5. Table with External Config Switches
 * SECTION 6. Sample Config

___________________________________________________________________________________
## Document Overview

This document contains instructions to deploy a pre-built Apache Fortress Rest web archive (war) to Tomcat and configure the server for its use.

-------------------------------------------------------------------------------
## SECTION 1. Prerequisites

Minimum software requirements:
 * Apache Tomcat7++
  * Completed either section in Apache Fortress Core Quickstart:
    * *SECTION 3. Apache Fortress Core Integration Test* in [README-QUICKSTART-SLAPD.md](https://github.com/apache/directory-fortress-core/blob/master/README-QUICKSTART-SLAPD.md)
    * *SECTION 4. Apache Fortress Core Integration Test* in [README-QUICKSTART-APACHEDS.md](https://github.com/apache/directory-fortress-core/blob/master/README-QUICKSTART-APACHEDS.md)

___________________________________________________________________________________
## SECTION 2. Configure Tomcat and Deploy Fortress Rest

Set the java system properties in tomcat with the target ldap server's coordinates.

1. Edit the startup script for Tomcat

2. Set the java opts

 a. For OpenLDAP:

 ```
 JAVA_OPTS="-Dversion=2.0.3 -Dfortress.admin.user=cn=Manager,dc=example,dc=com -Dfortress.admin.pw=secret -Dfortress.config.root=ou=Config,dc=example,dc=com"
 ```

 b. For ApacheDS:
 ```
 JAVA_OPTS="$JAVA_OPTS -Dfortress.admin.user=uid=admin,ou=system -Dfortress.admin.pw=secret -Dfortress.config.root=ou=Config,dc=example,dc=com -Dfortress.port=10389"
 ```

3. Verify these settings match your target LDAP server.

4. Download the fortress realm proxy jar into tomcat/lib folder:

  ```
  wget http://repo.maven.apache.org/maven2/org/apache/directory/fortress/fortress-realm-proxy/2.0.3/fortress-realm-proxy-2.0.3.jar -P $TOMCAT_HOME/lib
  ```

  where *TOMCAT_HOME* matches your target env.

5. Download the fortress rest war into tomcat/webapps folder:

  ```
  wget http://repo.maven.apache.org/maven2/org/apache/directory/fortress/fortress-rest/2.0.3/fortress-rest-2.0.3.war -P $TOMCAT_HOME/webapps
  ```

  where *TOMCAT_HOME* matches your target env.

6. Restart Tomcat.

___________________________________________________________________________________
## SECTION 3. Load Sample Security Policy

From the fortress core package perform the following steps:

1. Download the load file from git:

 ```
 wget https://github.com/apache/directory-fortress-enmasse/blob/master/src/main/resources/FortressRestServerPolicy.xml -P ldap/setup
 ```

2. Run maven install with load file:

 ```
 mvn install -Dload.file=ldap/setup/FortressRestServerPolicy.xml
 ```

 Note: This step must be completed before tests can be successfully run.

___________________________________________________________________________________
## SECTION 4. Test

1. Smoke test:

 ```
 mvn test -Dtest=EmTest
 ```

2. Complete *SECTION 7: Alternate testing procedures* in [Fortress Core README.md](https://github.com/apache/directory-fortress-enmasse/blob/master/README.md)
___________________________________________________________________________________
## SECTION 5. Table with External Config Switches

 Below is the list of Fortress config properties that can be set via Java System Property.  

|  #  |  Name                            | Sample Values                               |
| --- | -------------------------------- | ------------------------------------------- |
|   1 | fortress.host                    | localhost(default), myhostname, 10.14.74.28 |
|   2 | fortress.port                    | 389 (default), 636, 1389, 1636              |
|   3 | fortress.admin.user              | cn=manager,dc=example,dc=com                |
|   4 | fortress.admin.pw                | secret                                      |
|   5 | fortress.min.admin.conn          | 1                                           |
|   6 | fortress.max.admin.conn          | 10                                          |
|   7 | fortress.log.user                | cn=log                                      |
|   8 | fortress.log.pw                  | secret                                      |
|   9 | fortress.min.log.conn            | 1                                           |
|  10 | fortress.max.log.conn            | 5                                           |
|  11 | fortress.enable.ldap.ssl         | false(default), true                        |
|  12 | fortress.enable.ldap.starttls    | false(default), true                        |
|  13 | fortress.enable.ldap.ssl.debug   | false(default), true                        |
|  14 | fortress.trust.store             | mytruststore                                |
|  15 | fortress.trust.store.password    | changeit                                    |
|  16 | fortress.trust.store.onclasspath | false(default), true                        |
|  17 | fortress.config.realm            | default                                     |
|  18 | fortress.config.root             | ou=config,dc=example,dc=com                 |
|  19 | fortress.ldap.server.type        | apacheds, openldap, other                   |
|  20 | fortress.is.arbac02              | false(default), true                        |

___________________________________________________________________________________
## SECTION 6. Sample Config

 Setting Apache Fortress external configurations via Java System properties can be done using the startup scripts for the server instance. For example, the following are valid configurations.

 a. Connect to an OpenLDAP over localhost, port 389 (defaults) using unencrypted connections.  The runtime has ARBAC02 checks enabled.
 ```concept
JAVA_OPTS=" -Dversion=2.0.4-SNAPSHOT                            \ 
            -Dfortress.admin.user=cn=Manager,dc=example,dc=com  \ 
            -Dfortress.admin.pw=secret                          \ 
            -Dfortress.config.root=ou=Config,dc=example,dc=com  \
            -Dfortress.ldap.server.type=openldap                \
            -Dfortress.is.arbac02=true"
```
 b. Connect to ApacheDS server over an encrypted connection, the truststore found on the classpath.
 ```concept
JAVA_OPTS=" -Dversion=2.0.4-SNAPSHOT                             \
            -Dfortress.host=mydomainname.com                     \
            -Dfortress.port=1636                                 \
            -Dfortress.ldap.server.type=apacheds                 \             
            -Dfortress.admin.user=uid=admin,ou=system            \ 
            -Dfortress.admin.pw=secret                           \ 
            -Dfortress.config.root=ou=Config,dc=example,dc=com   \
            -Dfortress.enable.ldap.ssl=true"                     \
            -Dfortress.trust.store=mystruststore                 \
            -Dfortress.trust.store.password=changeit             \
            -Dfortress.trust.store.onclasspath=true
```

 c. This one OpenLDAP again, use encrypted connections, truststore located on fully qualified path.
 ```concept
JAVA_OPTS=" -Dversion=2.0.4-SNAPSHOT                                        \
            -Dfortress.host=mydomainname.com                                \
            -Dfortress.port=636                                             \
            -Dfortress.ldap.server.type=openldap                            \             
            -Dfortress.admin.user=cn=Manager,dc=example,dc=com              \ 
            -Dfortress.admin.pw=secret                                      \ 
            -Dfortress.config.root=ou=Config,dc=example,dc=com              \
            -Dfortress.enable.ldap.ssl=true"                                \
            -Dfortress.trust.store=/fully/qualified/file/name/mystruststore \
            -Dfortress.trust.store.password=changeit                        \
            -Dfortress.trust.store.onclasspath=false
```

#### END OF README-QUICKSTART