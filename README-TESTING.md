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
___________________________________________________________________________________
#### END OF README-TESTING
