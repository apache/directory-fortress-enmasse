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

-------------------------------------------------------------------------------
# README for Apache Fortress Rest Testing

-------------------------------------------------------------------------------
## Table of Contents

* SECTION 1. Testing Overview
* SECTION 2. Test with Curl
* SECTION 3. Test with Fortress Core
* SECTION 4. Troubleshooting

-------------------------------------------------------------------------------
## SECTION 1.  Testing Overview

This document describes two simple ways to test Apache Fortress Rest services:
- Use the curl utility to send HTTP requests to the Fortress Rest server.
- Use the Fortress Core to send requests to the server.

-------------------------------------------------------------------------------
## SECTION 2. Test with Curl

Follow the example in the Apache Fortress Quickstart testing guide:
- [APACHE FORTRESS QUICKSTART](https://github.com/shawnmckinney/apache-fortress-quickstart/blob/master/README-TESTING.md)

-------------------------------------------------------------------------------
## SECTION 3. Test with Fortress Core

These tests will use the Apache Fortress Core test programs to drive the Apache Fortress Rest services.
It works via fortress core's inherent ability to call itself over REST, useful for testing and hopping over firewalls.

```
            .-------'------.
            | FortressCore |
            '-------.------'
                    | HTTPS
            .-------'------.
            | FortressRest |
            '-------.------'
                    | in-process
            .-------'------.
            | FortressCore |
            '-------.------'
                    | LDAPS
          .---------'-------.
          | DirectoryServer |
          '-----------------'
```

1. Point your Apache Fortress Core test env to Apache Fortress REST runtime.

- Add these properties to slapd.properties or build.properties file:

```properties
enable.mgr.impl.rest=true

# This user account is added automatically during deployment of fortress-rest via -Dload.file=./src/main/resources/FortressRestServerPolicy.xml:
http.user=demouser4
http.pw=password
http.host=localhost
http.port=8080
http.protocol=http
```

2. Next, from **FORTRESS_CORE_HOME** enter the following command:

```bash
mvn install
```

- This will update the fortress.properties with the settings in the build.properties and slapd.properties files.

3. Now run the integration tests:

```bash
mvn -Dtest=FortressJUnitTest test
```

- The Apache Fortress Core tests run through the Apache Fortress Rest services.

4. Next, from **FORTRESS_CORE_HOME** enter the following command:

```bash
mvn test -Pconsole
```

- Console operations will now run through Apache Fortress Rest.

5. Run the jmeter load tests 

from **FORTRESS_CORE_HOME**:

```bash
mvn verify -Ploadtest -Dtype=...
```
- [README-LOAD-TESTING](https://github.com/apache/directory-fortress-core/blob/master/README-LOAD-TESTING.md)

-------------------------------------------------------------------------------
## SECTION 4. Troubleshooting

1. Error: Unable to find valid certification path to requested target 

Error in Fortress Core log:

```
2025-06-29 14:17:040 ERROR RestUtils:389 - post uri=[https://fortress-c:8443/fortress-rest-3.0.1-SNAPSHOT/], function=[cfgRead], caught IOException=PKIX path building failed: sun.security.provide
r.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
        at sun.security.ssl.Alert.createSSLException(Alert.java:131) ~[?:?]
        at sun.security.ssl.TransportContext.fatal(TransportContext.java:383) ~[?:?]
        at sun.security.ssl.TransportContext.fatal(TransportContext.java:326) ~[?:?]
        at sun.security.ssl.TransportContext.fatal(TransportContext.java:321) ~[?:?]
        at sun.security.ssl.CertificateMessage$T13CertificateConsumer.checkServerCerts(CertificateMessage.java:1351) ~[?:?]
       at sun.security.ssl.CertificateMessage$T13CertificateConsumer.onConsumeCertificate(CertificateMessage.java:1226) ~[?:?]
        at sun.security.ssl.CertificateMessage$T13CertificateConsumer.consume(CertificateMessage.java:1169) ~[?:?]
        at sun.security.ssl.SSLHandshake.consume(SSLHandshake.java:396) ~[?:?]
...
Caused by: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested t
...
2025-06-29 14:17:040 ERROR Config:825 - static init: Error loading from remote config: SecurityException=org.apache.directory.fortress.core.RestException: post uri=[https://fortress-c:8443/fortre
ss-rest-3.0.1-SNAPSHOT/], function=[cfgRead], caught IOException=PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to 
requested target
...
```

Solution:

a. Check the truststore params in the fortress properties:

```fortress.properties
trust.store=/opt/fortress/directory-fortress-core/config/truststore.jks
trust.store.password=changeit
trust.store.onclasspath=false
```

b. Correctly correspond in the runtime folder:

```bash
# ls -al /opt/fortress/directory-fortress-core/config/truststore.jks
-rw-r--r--. 1 root root 1910 Jun 29 14:03 /opt/fortress/directory-fortress-core/config/truststore.jks
```

c. Or, if the trust.store.onclasspath=true, that the file exists on the Java classpath of the Fortress Core runtime.


d. Verify the corresponding Java keystore is in place inside the tomcat/conf folder:

```bash
# ls -al /opt/tomcat/conf/keystore.jks 
-rw-r--r--. 1 tomcat tomcat 4524 Jun 29 14:11 /opt/tomcat/conf/keystore.jks
```

e. Verify the Java keystore's correctly configured in tomcat server.conf:

```
cat /opt/tomcat/conf/server.xml
...
<Connector                                                                                       
  protocol="org.apache.coyote.http11.Http11NioProtocol"                 
  port="8443" maxThreads="100" SSLEnabled="true">                         
  scheme="https" clientAuth="false"                                                              
  <SSLHostConfig>                                                                                
    <Certificate                                                                                 
      certificateKeystoreFile="conf/keystore.jks"
      certificateKeystorePassword="1Ec,Cc41OWuk:9vjNV.H"                        
      hostName="fortress-c"                                                                      
    />                                                                                           
  </SSLHostConfig>                                                                               
</Connector>             
```

f. If everything's correct and it still fails:

Try it again. There's a known bug, the first time fortress core attempts connect with Apache Tomcat it will fail with this error.

___________________________________________________________________________________
#### END OF README-TESTING
