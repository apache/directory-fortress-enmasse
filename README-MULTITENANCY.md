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
# README for Apache Fortress Rest Multitenancy Configuration

-------------------------------------------------------------------------------
## Table of Contents

 * SECTION 1. Multitenancy Overview
 * SECTION 2. Multitenant Fortress Realm Instance
 * SECTION 3. Multitenant Fortress Web Instance
 * SECTION 4. Rationale for setting a contextId in two locations

-------------------------------------------------------------------------------
## SECTION 1.  Multitenancy Overview

From Wikipedia:
* *Software Multitenancy refers to a software architecture in which a single instance of a software runs on a server and serves multiple tenants. A tenant is a group of users who share a common access with specific privileges to the software instance. With a multitenant architecture, a software application is designed to provide every tenant a dedicated share of the instance including its data, configuration, user management, tenant individual functionality and non-functional properties. Multitenancy contrasts with multi-instance architectures, where separate software instances operate on behalf of different tenants.*

 *Commentators regard multitenancy as an important feature of cloud computing.*

 https://en.wikipedia.org/wiki/Multitenancy

For an overview of how fortress multitenancy works:
 * [Fortress Core Multitenancy README](https://github.com/apache/directory-fortress-core/blob/master/README-MULTITENANCY.md)

-------------------------------------------------------------------------------
## SECTION 2.  Multitenant Fortress Realm Instance

Fortress Realm uses the tenant id inside the context.xml file:

 ```
 <Context path="/commander" reloadable="true">

    <Realm className="org.apache.directory.fortress.realm.tomcat.Tc7AccessMgrProxy"
           defaultRoles=""
           containerType="TomcatContext"
           realmClasspath=""
           contextId="HOME"
           />
 </Context>
 ```

 * In this example, all realm security checks are bound for the HOME tenant.

-------------------------------------------------------------------------------
## SECTION 3.  Multitenant Fortress Rest Instance

Fortress Rest uses the tenant id found inside the request *contextId* element:

 ```
 <FortRequest>
    <contextId>acme123</contextId>
    <entity xsi:type="permission" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <objName></objName>
        <opName></opName>
    </entity>
 </FortRequest>
 ```

 * This operation is scoped to tenat acme123's subtree.

___________________________________________________________________________________
## SECTION 4.  Rationale for setting a contextId in two locations

Why are there are two locations for setting the tenant id?

 * The setting in the meta-inf file determines where the caller's HTTP basic auth credentials are validated.
 * The contextId in the request determines the subtree the request's operation is bound to.
___________________________________________________________________________________
#### END OF README-MULTITENANCY