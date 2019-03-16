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

# README for Apache Fortress Security Model
 ![Apache Fortress Rest System Architecture](images/fortress-rest-system-arch.png "Apache Fortress Rest System Architecture")

___________________________________________________________________________________
## Table of Contents

 * Document Overview
 * Understand the security model of Apache Fortress Rest
 * Java EE security
 * Apache CXF's **SimpleAuthorizingInterceptor**
 * Apache Fortress **ARBAC02 Checks**

___________________________________________________________________________________

## Document Overview

Provides a description of the security mechanisms that may be applied during Apache Fortress REST operation.
___________________________________________________________________________________

## Understand the security model of Apache Fortress Rest

 * Apache Fortress Rest is a JAX-RS Web application that allows the Apache Fortress Core APIs to be called over an HTTP interface.
 * It deploys inside of any compliant Java Servlet container although here we'll be using Apache Tomcat.

### Apache Fortress Rest security model includes:

### TLS

Nothing special or unique going on here.  Refer to the documentation of your servlet container for how to enable.

___________________________________________________________________________________
## Java EE security

 * Apache Fortress Rest uses the [Apache Fortress Realm](https://github.com/apache/directory-fortress-realm) to provide Java EE authentication, coarse-grained authorization mapping the users and roles back to a given LDAP server.
 * The policy for Apache Fortress Rest is simple.  Any user with the **fortress-rest-user** role and correct credentials is allowed in.
 * The Fortress Rest interface uses HTTP Basic Auth tokens to send the userid/password.
___________________________________________________________________________________
## Apache CXF's **SimpleAuthorizingInterceptor**

This enforcement mechanism maps roles to a given set of services.  The following table shows what roles map to which (sets of) services:

| service type      | fortress-rest-super-user | fortress-rest-admin-user | fortress-rest-review-user | fortress-rest-access-user | fortress-rest-deladmin-user | fortress-rest-delreview-user | fortress-rest-delaccess-user | fortress-rest-pwmgr-user | fortress-rest-audit-user | fortress-rest-config-user |
| ----------------- | ------------------------ | ------------------------ | ------------------------- | ------------------------- | --------------------------- | ---------------------------- | ---------------------------- | ------------------------ | ------------------------ | ------------------------- |
| Admin  Manager    | true                     | true                     | false                     | false                     | false                       | false                        | false                        | false                    | false                    | false                     |
| Review Manager    | true                     | false                    | true                      | false                     | false                       | false                        | false                        | false                    | false                    | false                     |
| Access Manager    | true                     | false                    | false                     | true                      | false                       | false                        | false                        | false                    | false                    | false                     |
| Delegated Admin   | true                     | false                    | false                     | false                     | true                        | false                        | false                        | false                    | false                    | false                     |
| Delegated Review  | true                     | false                    | false                     | false                     | false                       | true                         | false                        | false                    | false                    | false                     |
| Delegated Access  | true                     | false                    | false                     | false                     | false                       | false                        | true                         | false                    | false                    | false                     |
| Password  Manager | true                     | false                    | false                     | false                     | false                       | false                        | false                        | true                     | false                    | false                     |
| Audit  Manager    | true                     | false                    | false                     | false                     | false                       | false                        | false                        | false                    | true                     | false                     |
| Config  Manager   | true                     | false                    | false                     | false                     | false                       | false                        | false                        | false                    | false                    | true                      |

___________________________________________________________________________________
## Apache Fortress **ARBAC02 Checks**

Disabled by default.  To enable, add this to fortress.properties file and restart instance:

```concept
# Boolean value. Disabled by default. If this is set to true, the runtime will enforce administrative permissions and ARBAC02 DA checks:
is.arbac02=true

```

These checks include the following:

1. All API invocations calls checkAccess on an admin perm corresponding with the API being called, e.g. AdminMgr.addUser.  This means at least one admin role activated for the caller has to have been granted that particular permission.

2. The assignUser, deassignUser, grantPermission, revokePermission APIs enforce administrative authority over the role being targeted. This is being done by establishing a range of roles (hierarchically), for which the target role falls inside.

For example, the following top-down role hierarchy:

```
       CTO
        |
    |       |
   ENG      QC
 |  |     |    |   
E1  E2   Q1    Q2
  |         |
 DA         QA
       |
       A
```
    
Where a role called 'CTO' is the highest ascendant, and 'A' is the lowest descendant. In a top-down role hierarchy, privilege increases as we descend in the tree.  So a person with role 'A' inherits all that are above.

In describing a range of roles, begin range is the lowest descendant in the chain, and end range the highest. Furthermore a bracket, '[', ']', indicates inclusiveness, whereas parenthesis indicates exclusiveness for a particular endpoint.

Some example ranges that can be derived:

 * [A, CTO] is the full set: {CTO, ENG, QC, E1, E2, Q1, Q2, DA, QA, A}. 
 * (A, CTO) is the full set, minus the endpoints: {ENG, QC, E1, E2, Q1, Q2, DA, QA}. 
 * [A, ENG] includes: {A, DA, E1, E2, ENG}, 
 * [A, ENG) includes: {A, DA, E1, E2}. 
 * etc... 

So, for an administrator to be able to target a role in one of the specified APIs above, at least one of their activated admin roles must pass the role range test.  There are currently two roles
created by the security policy in this project, that are excluded from this type of check:
fortress-rest-admin and fortress-core-super-admin

Which means they won't have to pass the role range test.  All others use the range field to define authority over a particular set of roles, in a hierarchical structure.
                                         
3. Some APIs on the AdminMgr do organization checks, matching the org on the admin role with that on the target.  There are two types of organziations, User and Permission.

For example, de/assignUser(User, Role) will verify that the caller has an admin role with a matching user org unit (UserOU) on the target role.
  
There is similar check on grant/revokePermission(Role, Permission), where the caller must have activated admin role matching the perm org unit (PermOU), corresponding with permission being targeted.

The complete list of APIs that enforce range and OU checks follow:

| API                            | Validate UserOU  | Validate PermOU | Range Check On Role | 
| ------------------------------ | ---------------- | ----------------| ------------------- | 
| AdminMgr.addUser               | true             | false           | false               | 
| AdminMgr.updateUser            | true             | false           | false               | 
| AdminMgr.deleteUser            | true             | false           | false               | 
| AdminMgr.disableUser           | true             | false           | false               | 
| AdminMgr.changePassword        | true             | false           | false               | 
| AdminMgr.resetPassword         | true             | false           | false               | 
| AdminMgr.lockUserAccount       | true             | false           | false               | 
| AdminMgr.unlockUserAccount     | true             | false           | false               | 
| AdminMgr.deletePasswordPolicy  | true             | false           | false               | 
| AdminMgr.assignUser            | true             | false           | true                | 
| AdminMgr.deassignUser          | true             | false           | true                | 
| AdminMgr.grantPermission       | false            | true            | true                | 
| AdminMgr.revokePermission      | false            | true            | true                | 


#### END OF README