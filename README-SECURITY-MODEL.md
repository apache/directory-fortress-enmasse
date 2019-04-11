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

# README for Apache Fortress REST Security Model
![Apache Fortress Rest Security Model](images/ApacheFortressRestSecurityModel.png "Apache Fortress Rest Security Model")

/home/smckinn/GIT/fortressDev/directory-fortress-enmasse/images/ApacheFortressRestSecurityModel.png
___________________________________________________________________________________
## Table of Contents

 * Document Overview
 * Understand the security model of Apache Fortress Rest
 * 1.TLS
 * 2.Java EE security
 * 3.Apache CXF's **SimpleAuthorizingInterceptor**
 * 4.Apache Fortress **ARBAC02 Checks**
 * The list of Services that enforce ARBAC02.
___________________________________________________________________________________

## Document Overview

 Provides a description of the various security mechanisms that are performed during Apache Fortress REST runtime operations.
___________________________________________________________________________________

## Understand the security model of Apache Fortress Rest

 * Apache Fortress Rest is a JAX-RS Web application that allows the Apache Fortress Core APIs to be called over an HTTP interface.
 * It deploys inside of any compliant Java Servlet container although here we'll be using Apache Tomcat.

### Apache Fortress Rest security model includes:

### 1. TLS

 Nothing special or unique going on here.  Refer to the documentation of your servlet container for how to enable.

___________________________________________________________________________________
## 2. Java EE security

 * Apache Fortress Rest uses the [Apache Fortress Realm](https://github.com/apache/directory-fortress-realm) to provide Java EE authentication, coarse-grained authorization mapping the users and roles back to a given LDAP server.
 * The policy for Apache Fortress Rest is simple.  Any user with the **fortress-rest-user** role and correct credentials is allowed in.
 * The Fortress Rest interface uses HTTP Basic Auth tokens to send the userid/password.
___________________________________________________________________________________
## 3. Apache CXF's **SimpleAuthorizingInterceptor**

This policy enforcement mechanism maps RBAC roles to a given set of services.  The following table shows what roles map to which (sets of) services:

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
## 4. Apache Fortress **ARBAC02 Checks**

 Disabled by default.  To enable, add this to fortress.properties file and restart instance:

 ```concept
# Boolean value. Disabled by default. If this is set to true, the runtime will enforce administrative permissions and ARBAC02 DA checks:
is.arbac02=true

 ```

The ARBAC checks when enabled, include the following:

a. All service invocations, except AccessMgr and DelAccessMgr, perform an ADMIN permission check automatically corresponding with the exact service/API being called. 
 
 For example, the permission with an objectName: **org.apache.directory.fortress.core.impl.AdminMgrImpl** and operation name: **addUser** is automatically checked
 during the call to the **userAdd** service.
    
 This means at least one ADMIN role must be activated for the user calling the service that has been granted the required permission.
 The entire list of permissions, and their mappings to services are listed in the table that follows.

b. Some services (#'s 1 - 12 listed below) perform organizational verification, comparing the org on the ADMIN role with that on the target user or permission in the HTTP request.
 There are two types of organizations being checked, User and Permission.  
 
 For example, **roleAsgn** and **roleDeasgn**  (9 and 10 below) will verify that the caller has an ADMIN role with a user org unit that matches the ou of the target user.  
 There is a similar check on **roleGrant** and **roleRevoke** (11 and 12) verifying the caller has an activated ADMIN role with a perm org unit that matches the ou on the target permission.

c. Some services (#'s 9,10,11,12) perform a range check on the target RBAC role to verify user has matching ADMIN role with authority to assign to user or grant to permission. 
 The Apache Fortress REST **roleAsgn**, **roleDeasgn**, **roleGrant** and **roleRevoke** services will enforce ADMIN authority over the particular RBAC role that is being targeted in the HTTP request. 
 These checks are based on a (hierarchical) range of roles, for which the target role must fall inside.   
 
 For example, the following top-down contains a sample RBAC role hierarchy for a fictional software development organization:

 ```
        CTO
         |
     |       |
    ENG      QC
   |   |   |    |   
  E1   E2  Q1   Q2
     |        |
    DA        QA
         |
         A1
 ```
    
 Here a role called *CTO* is the highest ascendant in the graph, and *A1* is the lowest descendant. In a top-down role hierarchy, privilege increases as we descend downward.  So a person with role *A1* inherits all that are above.

 In describing a range of roles, *beginRange* is the lowest descendant in the chain, and *endRange* the highest. Furthermore a bracket, '[', ']', indicates inclusiveness with an endpoint, whereas parenthesis, '(', ')' will exclude a corresponding endpoint.

 Some example ranges that can be derived from the sample role graph above:

 * [A1, CTO] is the full set: {CTO, ENG, QC, E1, E2, Q1, Q2, DA, QA, A1}. 
 * (A1, CTO) is the full set, minus the endpoints: {ENG, QC, E1, E2, Q1, Q2, DA, QA}. 
 * [A1, ENG] includes: {A1, DA, E1, E2, ENG}, 
 * [A1, ENG) includes: {A1, DA, E1, E2}. 
 * (QA, QC] has {Q1, Q2, QC} in its range.
 * etc... 

 For an administrator to be authorized to target an RBAC role in one of the specified APIs listed above, at least one of their activated ADMIN roles must pass the ARBAC role range test.  There are currently two roles 
 created by the security policy in this project, [FortressRestServerPolicy](./src/main/resources/FortressRestServerPolicy.xml), that are excluded from this type of check: 
 **fortress-rest-admin** and **fortress-core-super-admin**. 

 Which means they won't have to pass the role range test.  All others use the range field to define authority over a particular set of roles, in a hierarchical structure. 
                                         
### The list of Services that enforce ARBAC02.

|  #  | **Services**                   | UserOU Check | PermOU Check | Role Range Check | **ADMIN Permissions**                                                                             | 
| --- | ------------------------------ | ------------ | ------------ | ---------------- | ------------------------------------------------------------------------------------------------- |
|   1 | userAdd                        | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addUser"                   |
|   2 | userUpdate                     | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updateUser"                |
|   3 | userDelete                     | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteUser"                | 
|   4 | userDisable                    | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="disableUser"               |
|   5 | userChange                     | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="changePassword"            |
|   6 | userReset                      | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="resetPassword"             |
|   7 | userLock                       | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="lockUserAccount"           |
|   8 | userUnlock                     | true         | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="unlockUserAccount"         |
|   9 | roleAsgn                       | true         | false        | true             | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="assignUser"                |
|  10 | roleDeasgn                     | true         | false        | true             | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deassignUser"              |
|  11 | roleGrant                      | false        | true         | true             | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="grantPermission"           |
|  12 | roleRevoke                     | false        | true         | true             | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="revokePermission"          |
|  13 | roleAdd                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addRole"                   |
|  14 | roleDelete                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteRole"                |
|  15 | roleUpdate                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updateRole"                |
|  16 | addRoleConstraint              | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addRoleConstraint"         |
|  17 | removeRoleConstraint           | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="removeRoleConstraint"      |
|  18 | roleEnableConstraint           | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="enableRoleConstraint"      |
|  19 | roleDisableConstraint          | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="disableRoleConstraint"     |
|  20 | permAdd                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addPermission"             |
|  21 | objAdd                         | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addPermObj"                |
|  22 | permDelete                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deletePermission"          |
|  23 | objDelete                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deletePermObj"             |
|  24 | permUpdate                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updatePermission"          |
|  25 | objUpdate                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updatePermObj"             |
|  26 | userGrant                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="grantPermissionUser"       |
|  27 | userRevoke                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="revokePermissionUser"      |
|  28 | roleDescendant                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addDescendant"             |
|  29 | roleAscendent                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addAscendant"              |
|  30 | roleAddinherit                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addInheritance"            |
|  31 | roleDelinherit                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteInheritance"         |
|  32 | ssdAdd                         | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="createSsdSet"              |
|  33 | ssdUpdate                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updateSsdSet"              |
|  34 | ssdAddMember                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addSsdRoleMember"          |
|  35 | ssdDelMember                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteSsdRoleMember"       |
|  36 | ssdDelete                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteSsdSet"              |
|  37 | ssdCardUpdate                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="setSsdSetCardinality"      |
|  38 | dsdAdd                         | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="createDsdSet"              |
|  39 | dsdUpdate                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="updateDsdSet"              |
|  40 | dsdAddMember                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addDsdRoleMember"          |
|  41 | dsdDelMember                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteDsdRoleMember"       |
|  42 | dsdDelete                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deleteDsdSet"              |
|  43 | dsdCardUpdate                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="setDsdSetCardinality"      |
|  44 | addPermissionAttributeSet      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addPermissionAttributeSet" |
|  45 | deletePermissionAttributeSet   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="deletePermissionAttributeSet"|
|  46 | addPermissionAttributeToSet    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AdminMgrImpl" opName="addPermissionAttributeToSet" |
|  47 | permRead                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="readPermission"           |
|  48 | objRead                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="readPermObj"              |
|  49 | permSearch                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findPermissions"          |
|  50 | objSearch                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findPermObjs"             |
|  51 | permObjSearch                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findPermsByObj"           |
|  52 | roleRead                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="readRole"                 |
|  53 | roleSearch                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findRoles"                |
|  54 | userRead                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="readUser"                 |
|  55 | userSearch                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findUsers"                |
|  56 | userAsigned                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="assignedUsers"            |
|  57 | roleAsigned                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="assignedRoles"            |
|  58 | roleAuthzed                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="authorizedRoles"          |
|  59 | userAuthzed                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="authorizedUsers"          |
|  60 | rolePerms                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="rolePermissions"          |
|  61 | userPerms                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="userPermissions"          |
|  62 | permRoles                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="permissionRoles"          |
|  63 | permRolesAuthzed               | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="authorizedPermissionRoles"|
|  64 | permUsers                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="permissionUsers"          |
|  65 | permUsersAuthzed               | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="authorizedPermissionUsers"|
|  66 | ssdRoleSets                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="ssdRoleSets"              |
|  67 | ssdRead                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="ssdRoleSet"               |
|  68 | ssdRoles                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="ssdRoleSetRoles"          |
|  69 | ssdCard                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="ssdRoleSetCardinality"    |
|  70 | dsdRoleSets                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="dsdRoleSets"              |
|  71 | dsdSets                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="ssdSets"                  |
|  72 | dsdRead                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="dsdRoleSet"               |
|  73 | dsdRoles                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="dsdRoleSetRoles"          |
|  74 | dsdCard                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="dsdRoleSetCardinality"    |
|  75 | dsdSets                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="dsdSets"                  |
|  76 | readPermAttributeSet           | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="readPermAttributeSet"     |
|  77 | findRoleConstraints            | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.ReviewMgrImpl" opName="findRoleConstraints"      |
|  78 | arleAdd                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addRole"                |
|  79 | arleDelete                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="deleteRole"             |
|  80 | arleUpdate                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="updateRole"             |
|  81 | adminAssign                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="assignUser"             |
|  82 | adminDeassign                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="deassignUser"           |
|  83 | orgAdd                         | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addOU"                  |
|  84 | orgUpdate                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="updateOU"               |
|  85 | orgDelete                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="deleteOU"               |
|  86 | orgDescendant                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addDescendantOU"        |
|  87 | orgAscendent                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addAscendantOU"         |
|  88 | orgAddinherit                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addInheritanceOU"       |
|  89 | orgDelinherit                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="deleteInheritanceOU"    |
|  90 | arleDescendant                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addDescendantRole"      |
|  91 | arleAscendent                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addAscendantRole"       |
|  92 | arleAddinherit                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="addInheritanceRole"     |
|  93 | arleDelinherit                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelAdminMgrImpl" opName="deleteInheritanceRole"  |
|  94 | arleRead                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="readRole"              |
|  95 | arleSearch                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="findRoles"             |
|  96 | arleAsigned                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="assignedRoles"         |
|  97 | userAsignedAdmin               | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="assignedUsers"         |
|  98 | orgRead                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="readOU"                |
|  99 | orgSearch                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.DelReviewMgrImpl" opName="searchOU"              |
| 100 | groupAdd                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="add"                       |
| 101 | groupUpdate                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="update"                    |
| 102 | groupDelete                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="delete"                    |
| 103 | groupAsgn                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="assign"                    |
| 104 | groupDeasgn                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="deassign"                  |
| 105 | groupRead                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="read"                      |
| 106 | roleGroupAsigned               | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="groupRoles"                |
| 107 | groupAsigned                   | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.GroupMgrImpl" opName="roleGroups"                |
| 108 | pswdAdd                        | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="add"                    |
| 109 | pswdUpdate                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="update"                 |
| 110 | pswdDelete                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="delete"                 |
| 111 | pswdUserAdd                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="updateUserPolicy"       |
| 112 | pswdUserDelete                 | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="deletePasswordPolicy"   |
| 113 | pswdSearch                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="search"                 |
| 114 | pswdRead                       | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.PwPolicyMgrImpl" opName="read"                   |
| 115 | auditBinds                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="searchBinds"               |
| 116 | auditAuthzs                    | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="searchAuthZs"              |
| 117 | auditUserAuthzs                | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="getUserAuthZs"             |
| 118 | auditSessions                  | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="searchUserSessions"        |
| 119 | auditMods                      | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="searchAdminMods"           |
| 120 | auditInvld                     | false        | false        | false            | objName="org.apache.directory.fortress.core.impl.AuditMgrImpl" opName="searchInvalidUsers"        |
|     |                                | false        | false        | false            |   |


#### END OF README