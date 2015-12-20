/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.fortress.rest;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.rest.HttpIds;
import org.springframework.stereotype.Service;

/**
 * Implementation for EnMasse Service methods forwards to delegate.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Service("fortressService")
public class FortressServiceImpl implements FortressService
{
    // Instantiate the implementation classes where the actual work is done:
    private final ReviewMgrImpl reviewMgrImpl = new ReviewMgrImpl();
    private final AdminMgrImpl adminMgrImpl = new AdminMgrImpl();
    private final PswdPolicyMgrImpl pswdPolicyMgrImpl = new PswdPolicyMgrImpl();
    private final DelegatedAccessMgrImpl delegatedAccessMgrImpl = new DelegatedAccessMgrImpl();
    private final DelegatedReviewMgrImpl delegatedReviewMgrImpl = new DelegatedReviewMgrImpl();
    private final DelegatedAdminMgrImpl delegatedAdminMgrImpl = new DelegatedAdminMgrImpl();
    private final AccessMgrImpl accessMgrImpl = new AccessMgrImpl();
    private final AuditMgrImpl auditMgrImpl = new AuditMgrImpl();
    private final ConfigMgrImpl configMgrImpl = new ConfigMgrImpl();

    // These are the allowed roles for the Fortress Rest services:
    private static final String SUPER_USER = "fortress-rest-super-user";
    private static final String ACCESS_MGR_USER = "fortress-rest-access-user";
    private static final String ADMIN_MGR_USER = "fortress-rest-admin-user";
    private static final String REVIEW_MGR_USER = "fortress-rest-review-user";
    private static final String DELEGATED_ACCESS_MGR_USER = "fortress-rest-delaccess-user";
    private static final String DELEGATED_ADMIN_MGR_USER = "fortress-rest-deladmin-user";
    private static final String DELEGATED_REVIEW_MGR_USER = "fortress-rest-delreview-user";
    private static final String PASSWORD_MGR_USER = "fortress-rest-pwmgr-user";
    private static final String AUDIT_MGR_USER = "fortress-rest-audit-user";
    private static final String CONFIG_MGR_USER = "fortress-rest-config-user";

    /**
     * ************************************************************************************************************************************
     * BEGIN ADMINMGR
     * **************************************************************************************************************************************
     */

    /**
     * This command creates a new RBAC user. The command is valid only if the new user is
     * not already a member of the USERS data set. The USER data set is updated. The new user
     * does not own any session at the time of its creation.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#ou} - contains the name of an already existing User OU node</li>
     *   </ul>
     *   <h5>User optional parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#pwPolicy} - contains the name of an already existing OpenLDAP password policy node</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#cn} - maps to INetOrgPerson common name attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#sn} - maps to INetOrgPerson surname attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#description} - maps to INetOrgPerson description attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#phones} * - multi-occurring attribute maps to organizationalPerson telephoneNumber  attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#mobiles} * - multi-occurring attribute maps to INetOrgPerson mobile attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#emails} * - multi-occurring attribute maps to INetOrgPerson mail attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#address} * - multi-occurring attribute maps to organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginTime} - HHMM - determines begin hour user may activate session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endTime} - HHMM - determines end hour user may activate session.</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginDate} - YYYYMMDD - determines date when user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endDate} - YYYYMMDD - indicates latest date user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#timeout} - number in seconds of session inactivity time allowed</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#props} * - multi-occurring attribute contains property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the name of already existing role to assign to user</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains the name of already existing adminRole to assign to user</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addUser( FortRequest request )
    {
        return adminMgrImpl.addUser( request );
    }

    
    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * This method performs a "hard" delete.  It completely removes all data associated with this user from the directory.
     * User entity must exist in directory prior to making this call else exception will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteUser( FortRequest request )
    {
        return adminMgrImpl.deleteUser( request );
    }

    
    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * Method performs a "soft" delete.  It performs the following:
     * <ul>
     *   <li>sets the user status to "deleted"</li>
     *   <li>deassigns all roles from the user</li>
     *   <li>locks the user's password in LDAP</li>
     *   <li>revokes all perms that have been granted to user entity.</li>
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_DISABLE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse disableUser( FortRequest request )
    {
        return adminMgrImpl.disableUser( request );
    }
    

    /**
     * This method performs an update on User entity in directory.  Prior to making this call the entity must exist in
     * directory.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *   </ul>
     *   <h5>User optional parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#ou} - contains the name of an already existing User OU node</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#pwPolicy} - contains the name of an already existing OpenLDAP password policy node</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#cn} - maps to INetOrgPerson common name attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#sn} - maps to INetOrgPerson surname attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#description} - maps to INetOrgPerson description attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#phones} * - multi-occurring attribute maps to organizationalPerson telephoneNumber  attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#mobiles} * - multi-occurring attribute maps to INetOrgPerson mobile attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#emails} * - multi-occurring attribute maps to INetOrgPerson mail attribute</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#address} * - multi-occurring attribute maps to organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginTime} - HHMM - determines begin hour user may activate session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endTime} - HHMM - determines end hour user may activate session.</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginDate} - YYYYMMDD - determines date when user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endDate} - YYYYMMDD - indicates latest date user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of user may sign on</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#timeout} - number in seconds of session inactivity time allowed</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#props} * - multi-occurring attribute contains property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the name of already existing role to assign to user</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains the name of already existing adminRole to assign to user</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updateUser( FortRequest request )
    {
        return adminMgrImpl.updateUser( request );
    }

    
    /**
     * Method will change user's password.  This method will evaluate user's password policies.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *     <li>{@link org.apache.directory.fortress.core.model.User#password} - contains the User's old password</li>
     *     <li>newPassword - contains the User's new password</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_CHGPW + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse changePassword( FortRequest request )
    {
        return adminMgrImpl.changePassword( request );
    }

    
    /**
     * Method will lock user's password which will prevent the user from authenticating with directory.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_LOCK + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse lockUserAccount( FortRequest request )
    {
        return adminMgrImpl.lockUserAccount( request );
    }

    
    /**
     * Method will unlock user's password which will enable user to authenticate with directory.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_UNLOCK + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse unlockUserAccount( FortRequest request )
    {
        return adminMgrImpl.unlockUserAccount( request );
    }

    
    /**
     * Method will reset user's password which will require user to change password before successful authentication with directory.
     * This method will not evaluate password policies on the new user password as it must be changed before use.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object</li>
     *   <h5>User required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *     <li>newPassword - contains the User's new password</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_RESET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse resetPassword( FortRequest request )
    {
        return adminMgrImpl.resetPassword( request );
    }

    
    /**
     * This command creates a new role. The command is valid if and only if the new role is not
     * already a member of the ROLES data set. The ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object</li>
     *   <h4>Role required parameters</h4>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to be created.</li>
     *   </ul>
     * </ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#description} - maps to description attribute on organizationalRole object class</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *   <li>{@link org.apache.directory.fortress.core.model.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addRole( FortRequest request )
    {
        return adminMgrImpl.addRole( request );
    }

    
    /**
     * This command deletes an existing role from the RBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ROLES data set.  This command will
     * also deassign role from all users.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object</li>
     *   <h4>Role required parameters</h4>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to be removed.</li>
     *   </ul>
     * <ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteRole( FortRequest request )
    {
        return adminMgrImpl.deleteRole( request );
    }

    
    /**
     * Method will update a Role entity in the directory.  The role must exist in role container prior to this call.     *
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object</li>
     * <h4>Role required parameters</h4>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to be updated.</li>
     * </ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#description} - maps to description attribute on organizationalRole object class</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link org.apache.directory.fortress.core.model.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updateRole( FortRequest request )
    {
        return adminMgrImpl.updateRole( request );
    }

    
    /**
     * This command assigns a user to a role.
     * <ul>
     *   <li> The command is valid if and only if:
     *   <li> The user is a member of the USERS data set
     *   <li> The role is a member of the ROLES data set
     *   <li> The user is not already assigned to the role
     *   <li> The SSD constraints are satisfied after assignment.
     * </ul>
     * <p>
     * Successful completion of this op, the following occurs:
     * <ul>
     *   <li> User entity (resides in people container) has role assignment added to aux object class attached to actual user record.
     *   <li> Role entity (resides in role container) has userId added as role occupant.
     *   <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:
     *   <ul>
     *     <li> timeout - number in seconds of session inactivity time allowed.
     *     <li> beginDate - YYYYMMDD - determines date when role may be activated.
     *     <li> endDate - YYMMDD - indicates latest date role may be activated.
     *     <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status
     *     <li> endLockDate - YYMMDD - determines end of enforced inactive status.
     *     <li> beginTime - HHMM - determines begin hour role may be activated in user's session.
     *     <li> endTime - HHMM - determines end hour role may be activated in user's session.*
     *     <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.
     *   </ul>
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} object</li>
     *   <h5>UserRole required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing Role to be assigned</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId for existing User</li>
     *   </ul>
     *   <h5>UserRole optional parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ASGN + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse assignUser( FortRequest request )
    {
        return adminMgrImpl.assignUser( request );
    }

    
    /**
     * This command deletes the assignment of the User from the Role entities. The command is
     * valid if and only if the user is a member of the USERS data set, the role is a member of
     * the ROLES data set, and the user is assigned to the role.
     * Any sessions that currently have this role activated will not be effected.
     * Successful completion includes:
     * User entity in USER data set has role assignment removed.
     * Role entity in ROLE data set has userId removed as role occupant.
     * (optional) Temporal constraints will be removed from user aux object if set prior to call.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} object</li>
     * <h5>UserRole required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing Role to be deassigned</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId for existing User</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DEASGN + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deassignUser( FortRequest request )
    {
        return adminMgrImpl.deassignUser( request );
    }

    
    /**
     * This method will add permission operation to an existing permission object which resides under {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may have {@link org.apache.directory.fortress.core.model.Role} or {@link org.apache.directory.fortress.core.model.User} associations.  The target {@link org.apache.directory.fortress.core.model.Permission} must not exist prior to calling.
     * A Fortress Permission instance exists in a hierarchical, one-many relationship between its parent and itself as stored in ldap tree: ({@link org.apache.directory.fortress.core.model.PermObj}*->{@link org.apache.directory.fortress.core.model.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted for the permission add</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission operation being added</li>
     * </ul>
     * <h5>Permission optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#roles} * - multi occurring attribute contains RBAC Roles that permission operation is being granted to</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#users} * - multi occurring attribute contains Users that permission operation is being granted to</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#type} - any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PERM_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addPermission( FortRequest request )
    {
        return adminMgrImpl.addPermission( request );
    }

    
    /**
     * This method will update permission operation pre-existing in target directory under {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may also contain {@link org.apache.directory.fortress.core.model.Role} or {@link org.apache.directory.fortress.core.model.User} associations to add or remove using this function.
     * The perm operation must exist before making this call.  Only non-null attributes will be updated.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted for the permission update</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission operation being updated</li>
     * </ul>
     * <h5>Permission optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#roles} * - multi occurring attribute contains RBAC Roles that permission operation is being granted to</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#users} * - multi occurring attribute contains Users that permission operation is being granted to</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#type} - any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PERM_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updatePermission( FortRequest request )
    {
        return adminMgrImpl.updatePermission( request );
    }

    
    /**
     * This method will remove permission operation entity from permission object. A Fortress permission is (object->operation).
     * The perm operation must exist before making this call.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted for the permission removal</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission operation being deleted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PERM_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deletePermission( FortRequest request )
    {
        return adminMgrImpl.deletePermission( request );
    }

    
    /**
     * This method will add permission object to perms container in directory. The perm object must not exist before making this call.
     * A {@link org.apache.directory.fortress.core.model.PermObj} instance exists in a hierarchical, one-many relationship between itself and children as stored in ldap tree: ({@link org.apache.directory.fortress.core.model.PermObj}*->{@link org.apache.directory.fortress.core.model.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object being added</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#ou} - contains the name of an existing PERMS OrgUnit this object is associated with</li>
     * </ul>
     * <h5>PermObj optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#description} - any safe text</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#type} - contains any safe text</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.OBJ_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addPermObj( FortRequest request )
    {
        return adminMgrImpl.addPermObj( request );
    }

    
    /**
     * This method will update permission object in perms container in directory.  The perm object must exist before making this call.
     * A {@link org.apache.directory.fortress.core.model.PermObj} instance exists in a hierarchical, one-many relationship between itself and children as stored in ldap tree: ({@link org.apache.directory.fortress.core.model.PermObj}*->{@link org.apache.directory.fortress.core.model.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object being updated</li>
     * </ul>
     * <h5>PermObj optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#ou} - contains the name of an existing PERMS OrgUnit this object is associated with</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#description} - any safe text</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#type} - contains any safe text</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.OBJ_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updatePermObj( FortRequest request )
    {
        return adminMgrImpl.updatePermObj( request );
    }

    
    /**
     * This method will remove permission object to perms container in directory.  This method will also remove
     * in associated permission objects that are attached to this object.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object being removed</li>
     * </ul>
     * </ul>
     * <h5>optional parameters</h5>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.OBJ_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deletePermObj( FortRequest request )
    {
        return adminMgrImpl.deletePermObj( request );
    }

    
    /**
     * This command grants a role the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the role is a member of the ROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#roleNm} - contains the role name</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_GRANT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse grant( FortRequest request )
    {
        return adminMgrImpl.grant(request, this);
    }

    
    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a role. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the role is a member of the ROLES data set, and the permission is assigned to that role.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#roleNm} - contains the role name</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_REVOKE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse revoke( FortRequest request )
    {
        return adminMgrImpl.revoke(request, this);
    }

    
    /**
     * This command grants a user the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_GRANT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse grantUser( FortRequest request )
    {
        return adminMgrImpl.grantUser(request, this);
    }

    
    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a user. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the user is a member of the USERS data set, and the permission is assigned to that user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.USER_REVOKE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse revokeUser( FortRequest request )
    {
        return adminMgrImpl.revokeUser(request, this);
    }

    
    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     * <li> The childRole is not a member of the ROLES data set.
     * <li> The parentRole is a member of the ROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new role.
     * <li> Assigns role relationship between new childRole and pre-existing parentRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing parent role</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of new child role</li>
     * </ul>
     * <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#description} - maps to description attribute on organizationalRole object class for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DESC + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addDescendant( FortRequest request )
    {
        return adminMgrImpl.addDescendant( request );
    }

    
    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole is not a member of the ROLES data set.
     * <li> The childRole is a member of the ROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new role.
     * <li> Assigns role relationship between new parentRole and pre-existing childRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>childRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing child Role</li>
     * <li>parentRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of new Role to be parent</li>
     * </ul>
     * <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#description} - maps to description attribute on organizationalRole object class for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ASC + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addAscendant( FortRequest request )
    {
        return adminMgrImpl.addAscendant( request );
    }

    
    /**
     * This commands establishes a new immediate inheritance relationship parentRole <<-- childRole between existing
     * roles parentRole, childRole.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole and childRole are members of the ROLES data set.
     * <li> The parentRole is not an immediate ascendant of childRole.
     * <li> The childRole does not properly inherit parentRole (in order to avoid cycle creation).
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing role to be parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing role to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ADDINHERIT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addInheritance( FortRequest request )
    {
        return adminMgrImpl.addInheritance( request );
    }

    
    /**
     * This command deletes an existing immediate inheritance relationship parentRole <<-- childRole.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The roles parentRole and childRole are members of the ROLES data set.
     * <li> The parentRole is an immediate ascendant of childRole.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parentRole <<-- childRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing Role to remove parent relationship</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing Role to remove child relationship</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DELINHERIT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteInheritance( FortRequest request )
    {
        return adminMgrImpl.deleteInheritance( request );
    }

    
    /**
     * This command creates a named SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the SSD set is not already in use.
     * <li> All the roles in the SSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     * <li> The SSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of new SSD role set to be added</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse createSsdSet( FortRequest request )
    {
        return adminMgrImpl.createSsdSet( request );
    }

    
    /**
     * This command updates existing SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the SSD set exists in directory.
     * <li> All the roles in the SSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     * <li> The SSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set to be modified</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updateSsdSet( FortRequest request )
    {
        return adminMgrImpl.updateSsdSet( request );
    }


    /**
     * This command adds a role to a named SSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The role to be added is a member of the ROLES data set but not of a member of the SSD role set.
     * <li> The SSD constraint is satisfied after the addition of the role to the SSD role set.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to add as member to SSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_ADD_MEMBER + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addSsdRoleMember( FortRequest request )
    {
        return adminMgrImpl.addSsdRoleMember( request );
    }

    
    /**
     * This command removes a role from a named SSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The role to be removed is a member of the SSD role set.
     * <li> The cardinality associated with the SSD role set is less than the number of elements of the SSD role set.
     * </ul>
     * Note that the SSD constraint should be satisfied after the removal of the role from the SSD role set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to remove as member to SSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_DEL_MEMBER + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteSsdRoleMember( FortRequest request )
    {
        return adminMgrImpl.deleteSsdRoleMember( request );
    }

    
    /**
     * This command deletes a SSD role set completely. The command is valid if and only if the SSD role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set targeted for removal</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteSsdSet( FortRequest request )
    {
        return adminMgrImpl.deleteSsdSet( request );
    }

    
    /**
     * This command sets the cardinality associated with a given SSD role set.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of elements of the SSD role set.
     * <li> The SSD constraint is satisfied after setting the new cardinality.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - contains new cardinality setting for SSD</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.SSD_CARD_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse setSsdSetCardinality( FortRequest request )
    {
        return adminMgrImpl.setSsdSetCardinality( request );
    }

    
    /**
     * This command creates a named DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the DSD set is not already in use.
     * <li> All the roles in the DSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     * <li> The DSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of new DSD role set to be added</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse createDsdSet( FortRequest request )
    {
        return adminMgrImpl.createDsdSet( request );
    }

    
    /**
     * This command updates existing DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the DSD set exists in directory.
     * <li> All the roles in the DSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     * <li> The DSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set to be modified</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updateDsdSet( FortRequest request )
    {
        return adminMgrImpl.updateDsdSet( request );
    }

    
    /**
     * This command adds a role to a named DSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The role to be added is a member of the ROLES data set but not of a member of the DSD role set.
     * <li> The DSD constraint is satisfied after the addition of the role to the DSD role set.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to add as member to DSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_ADD_MEMBER + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addDsdRoleMember( FortRequest request )
    {
        return adminMgrImpl.addDsdRoleMember( request );
    }

    
    /**
     * This command removes a role from a named DSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The role to be removed is a member of the DSD role set.
     * <li> The cardinality associated with the DSD role set is less than the number of elements of the DSD role set.
     * </ul>
     * Note that the DSD constraint should be satisfied after the removal of the role from the DSD role set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to remove as member to DSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_DEL_MEMBER + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteDsdRoleMember( FortRequest request )
    {
        return adminMgrImpl.deleteDsdRoleMember( request );
    }

    
    /**
     * This command deletes a DSD role set completely. The command is valid if and only if the DSD role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set targeted for removal</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteDsdSet( FortRequest request )
    {
        return adminMgrImpl.deleteDsdSet( request );
    }

    
    /**
     * This command sets the cardinality associated with a given DSD role set.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of elements of the DSD role set.
     * <li> The DSD constraint is satisfied after setting the new cardinality.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#cardinality} - contains new cardinality setting for DSD</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.SDSet}
     */
    @POST
    @Path("/" + HttpIds.DSD_CARD_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse setDsdSetCardinality( FortRequest request )
    {
        return adminMgrImpl.setDsdSetCardinality( request );
    }

    
    /**
     * ************************************************************************************************************************************
     * BEGIN REVIEWMGR
     * **************************************************************************************************************************************
     */
    /**
     * This method returns a matching permission entity to caller.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.Permission}
     */
    @POST
    @Path("/" + HttpIds.PERM_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readPermission( FortRequest request )
    {
        return reviewMgrImpl.readPermission( request );
    }

    
    /**
     * Method reads permission object from perm container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PermObj} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.PermObj}
     */
    @POST
    @Path("/" + HttpIds.OBJ_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readPermObj( FortRequest request )
    {
        return reviewMgrImpl.readPermObj( request );
    }

    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more leading characters of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains one or more leading characters of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Permission}
     */
    @POST
    @Path("/" + HttpIds.PERM_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findPermissions( FortRequest request )
    {
        return reviewMgrImpl.findPermissions( request );
    }


    /**
     * Method returns Permision operations for the provided permission object.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more leading characters of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Permission}
     */
    @POST
    @Path("/" + HttpIds.PERM_OBJ_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findObjPermissions( FortRequest request )
    {
        return reviewMgrImpl.findObjPermissions( request );
    }


    /**
     * Method returns a list of type Permission that match any part of either {@link org.apache.directory.fortress.core.model.Permission#objName} or {@link org.apache.directory.fortress.core.model.Permission#opName} search strings.
     * This method differs from findPermissions in that any permission that matches any part of the perm obj or any part of the perm op will be returned in result set (uses substring string matching).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more substring characters of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains one or more substring characters of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Permission}
     */
    @POST
    @Path("/" + HttpIds.PERM_SEARCH_ANY + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findAnyPermissions( FortRequest request )
    {
        return reviewMgrImpl.findAnyPermissions( request );
    }


    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PermObj} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PermObj#objName} - contains one or more characters of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.PermObj}
     */
    @POST
    @Path("/" + HttpIds.OBJ_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findPermObjs( FortRequest request )
    {
        return reviewMgrImpl.findPermObjs( request );
    }

    
    /**
     * Method reads Role entity from the role container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to read.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.Role}
     */
    @POST
    @Path("/" + HttpIds.ROLE_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readRole( FortRequest request )
    {
        return reviewMgrImpl.readRole( request );
    }

    
    /**
     * Method will return a list of type Role matching all or part of {@link org.apache.directory.fortress.core.model.Role#name}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains all or some of the chars corresponding to role entities stored in directory.</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Role}
     */
    @POST
    @Path("/" + HttpIds.ROLE_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findRoles( FortRequest request )
    {
        return reviewMgrImpl.findRoles( request );
    }

    
    /**
     * Method returns matching User entity that is contained within the people container in the directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the User object targeted for read.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.User}
     */
    @POST
    @Path("/" + HttpIds.USER_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readUser( FortRequest request )
    {
        return reviewMgrImpl.readUserM( request );
    }

    
    /**
     * Return a list of type User of all users in the people container that match all or part of the {@link org.apache.directory.fortress.core.model.User#userId} or {@link org.apache.directory.fortress.core.model.User#ou} fields passed in User entity.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains all or some leading chars that match userId(s) stored in the directory.</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#ou} - contains one or more characters of org unit associated with existing object(s) being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.User}
     */
    @POST
    @Path("/" + HttpIds.USER_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findUsers( FortRequest request )
    {
        return reviewMgrImpl.findUsersM( request );
    }

    
    /**
     * This method returns the data set of all users who are assigned the given role.  This searches the User data set for
     * Role relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.User}
     */
    @POST
    @Path("/" + HttpIds.USER_ASGNED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedUsers( FortRequest request )
    {
        return reviewMgrImpl.assignedUsersM( request );
    }

    
    /**
     * This function returns the set of roles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.UserRole}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ASGNED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedRoles( FortRequest request )
    {
        return reviewMgrImpl.assignedRolesM( request );
    }

    
    /**
     * This function returns the set of users authorized to a given role, i.e., the users that are assigned to a role that
     * inherits the given role. The function is valid if and only if the given role is a member of the ROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.User}
     */
    @POST
    @Path("/" + HttpIds.ROLE_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedUsers( FortRequest request )
    {
        return reviewMgrImpl.authorizedUsersM( request );
    }

    
    /**
     * This function returns the set of roles authorized for a given user. The function is valid if
     * and only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing the User's authorized role names.
     */
    @POST
    @Path("/" + HttpIds.USER_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedRoles( FortRequest request )
    {
        return reviewMgrImpl.authorizedRoleM( request );
    }

    
    /**
     * Return a list of type String of all roles that have granted a particular permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing role names that permission has been granted to.
     */
    @POST
    @Path("/" + HttpIds.PERM_ROLES + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse permissionRoles( FortRequest request )
    {
        return reviewMgrImpl.permissionRolesM( request );
    }

    
    /**
     * This function returns the set of all permissions (op, obj), granted to or inherited by a
     * given role. The function is valid if and only if the role is a member of the ROLES data
     * set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Permission} containing permissions for role.
     */
    @POST
    @Path("/" + HttpIds.ROLE_PERMS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse rolePermissions( FortRequest request )
    {
        return reviewMgrImpl.rolePermissionsM( request );
    }

    
    /**
     * This function returns the set of permissions a given user gets through his/her authorized
     * roles. The function is valid if and only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.Permission} containing permissions for user.
     */
    @POST
    @Path("/" + HttpIds.USER_PERMS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse userPermissions( FortRequest request )
    {
        return reviewMgrImpl.userPermissionsM( request );
    }

    
    /**
     * Return all role names that have been authorized for a given permission.  This will process role hierarchies to determine set of all Roles who have access to a given permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing role names that permission has been granted to.
     */
    @POST
    @Path("/" + HttpIds.PERM_ROLES_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedPermissionRoles( FortRequest request )
    {
        return reviewMgrImpl.authorizedPermissionRolesM( request );
    }

    
    /**
     * Return all userIds that have been granted (directly) a particular permission.  This will not consider assigned or authorized Roles.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing userIds that permission has been granted to.
     */
    @POST
    @Path("/" + HttpIds.PERM_USERS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse permissionUsers( FortRequest request )
    {
        return reviewMgrImpl.permissionUsersM( request );
    }

    
    /**
     * Return all userIds that have been authorized for a given permission.  This will process role hierarchies to determine set of all Users who have access to a given permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing userIds that permission is authorized for.
     */
    @POST
    @Path("/" + HttpIds.PERM_USERS_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedPermissionUsers( FortRequest request )
    {
        return reviewMgrImpl.authorizedPermissionUsersM( request );
    }

    
    /**
     * This function returns the list of all SSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all SSD role sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.SDSet} containing all matching SSD sets.
     */
    @POST
    @Path("/" + HttpIds.SSD_ROLE_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse ssdRoleSets( FortRequest request )
    {
        return reviewMgrImpl.ssdRoleSetsM( request );
    }

    
    /**
     * This function returns the SSD data set that matches a particular set name.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type {@link org.apache.directory.fortress.core.model.SDSet} containing matching SSD set.
     */
    @POST
    @Path("/" + HttpIds.SSD_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse ssdRoleSet( FortRequest request )
    {
        return reviewMgrImpl.ssdRoleSetM( request );
    }

    
    /**
     * This function returns the set of roles of a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing all member roles of SSD set.
     */
    @POST
    @Path("/" + HttpIds.SSD_ROLES + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse ssdRoleSetRoles( FortRequest request )
    {
        return reviewMgrImpl.ssdRoleSetRolesM( request );
    }

    
    /**
     * This function returns the cardinality associated with a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>name contains the name of existing SSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    @POST
    @Path("/" + HttpIds.SSD_CARD + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse ssdRoleSetCardinality( FortRequest request )
    {
        return reviewMgrImpl.ssdRoleSetCardinalityM( request );
    }

    
    /**
     * This function returns the list of all SSD sets that have a particular SSD set name.
     * If the parameter is left blank, function will return all SSD sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name to use for the search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.SDSet} containing all matching SSD sets.
     */
    @POST
    @Path("/" + HttpIds.SSD_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse ssdSets( FortRequest request )
    {
        return reviewMgrImpl.ssdSetsM( request );
    }

    
    /**
     * This function returns the list of all DSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all DSD role sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.SDSet} containing all matching DSD sets.
     */
    @POST
    @Path("/" + HttpIds.DSD_ROLE_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse dsdRoleSets( FortRequest request )
    {
        return reviewMgrImpl.dsdRoleSetsM( request );
    }

    
    /**
     * This function returns the DSD data set that matches a particular set name.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type {@link org.apache.directory.fortress.core.model.SDSet} containing matching DSD set.
     */
    @POST
    @Path("/" + HttpIds.DSD_READ + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse dsdRoleSet( FortRequest request )
    {
        return reviewMgrImpl.dsdRoleSetM( request );
    }

    
    /**
     * This function returns the set of roles of a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing all member roles of DSD set.
     */
    @POST
    @Path("/" + HttpIds.DSD_ROLES + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse dsdRoleSetRoles( FortRequest request )
    {
        return reviewMgrImpl.dsdRoleSetRolesM( request );
    }

    
    /**
     * This function returns the cardinality associated with a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>name contains the name of existing DSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    @POST
    @Path("/" + HttpIds.DSD_CARD + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse dsdRoleSetCardinality( FortRequest request )
    {
        return reviewMgrImpl.dsdRoleSetCardinalityM( request );
    }

    
    /**
     * This function returns the list of all DSD sets that have a particular DSD set name.
     * If the parameter is left blank, function will return all DSD sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name to use for the search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.SDSet} containing all matching DSD sets.
     */
    @POST
    @Path("/" + HttpIds.DSD_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse dsdSets( FortRequest request )
    {
        return reviewMgrImpl.dsdSetsM( request );
    }

    
    /**
     * ************************************************************************************************************************************
     * BEGIN ACCESSMGR
     * **************************************************************************************************************************************
     */
    /**
     * Perform user authentication only.  It does not activate RBAC roles in session but will evaluate
     * password policies.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will be returned if authentication successful.  This will not contain user's roles.
     */
    @POST
    @Path("/" + HttpIds.RBAC_AUTHN + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse authenticate( FortRequest request )
    {
        return accessMgrImpl.authenticate( request );
    }

    
    /**
     * Perform user authentication {@link org.apache.directory.fortress.core.model.User#password} and role activations.<br />
     * This method must be called once per user prior to calling other methods within this class.
     * The successful result is {@link org.apache.directory.fortress.core.model.Session} that contains target user's RBAC {@link org.apache.directory.fortress.core.model.User#roles} and Admin role {@link org.apache.directory.fortress.core.model.User#adminRoles}.<br />
     * In addition to checking user password validity it will apply configured password policy checks {@link org.apache.directory.fortress.core.model.User#pwPolicy}..<br />
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the names of assigned RBAC roles targeted for activation into Session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains the names of assigned ARBAC roles targeted for activation into Session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected on behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     * </ul>
     * </ul>
     * <h4> This API will...</h4>
     * <ul>
     * <li> authenticate user password.
     * <li> perform <a href="http://www.openldap.org/">OpenLDAP</a> <a href="http://tools.ietf.org/html/draft-behera-ldap-password-policy-10">password policy evaluation</a>.
     * <li> fail for any user who is locked by OpenLDAP's policies {@link org.apache.directory.fortress.core.model.User#isLocked()}.
     * <li> evaluate temporal {@link org.apache.directory.fortress.core.util.time.Constraint}(s) on {@link org.apache.directory.fortress.core.model.User}, {@link org.apache.directory.fortress.core.model.UserRole} and {@link org.apache.directory.fortress.core.model.UserAdminRole} entities.
     * <li> process selective role activations into User RBAC Session {@link org.apache.directory.fortress.core.model.User#roles}.
     * <li> check Dynamic Separation of Duties {@link org.apache.directory.fortress.core.model.DSDChecker#validate(org.apache.directory.fortress.core.model.Session, org.apache.directory.fortress.core.util.time.Constraint, org.apache.directory.fortress.core.util.time.Time)} on {@link org.apache.directory.fortress.core.model.User#roles}.
     * <li> process selective administrative role activations {@link org.apache.directory.fortress.core.model.User#adminRoles}.
     * <li> return a {@link org.apache.directory.fortress.core.model.Session} containing {@link org.apache.directory.fortress.core.model.Session#getUser()}, {@link org.apache.directory.fortress.core.model.Session#getRoles()} and (if admin user) {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()} if everything checks out good.
     * <li> return a checked exception that will be {@link org.apache.directory.fortress.core.SecurityException} or its derivation.
     * <li> return a {@link org.apache.directory.fortress.core.SecurityException} for system failures.
     * <li> return a {@link org.apache.directory.fortress.core.PasswordException} for authentication and password policy violations.
     * <li> return a {@link org.apache.directory.fortress.core.ValidationException} for data validation errors.
     * <li> return a {@link org.apache.directory.fortress.core.FinderException} if User id not found.
     * <li> (optionally) store parms passed in by client for audit trail purposes.
     * </ul>
     * <h4>
     * The function is valid if and only if:
     * </h4>
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the password is supplied (unless trusted).
     * <li> the (optional) active role set is a subset of the roles authorized for that user.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result code {@link org.apache.directory.fortress.core.model.Session#errorId}, RBAC role activations {@link org.apache.directory.fortress.core.model.Session#getRoles()}, Admin Role activations {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()},OpenLDAP pw policy codes {@link org.apache.directory.fortress.core.model.Session#getWarnings()}, {@link org.apache.directory.fortress.core.model.Session#expirationSeconds}, {@link org.apache.directory.fortress.core.model.Session#graceLogins} and more.
     */
    @POST
    @Path("/" + HttpIds.RBAC_CREATE + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse createSession( FortRequest request )
    {
        return accessMgrImpl.createSession( request );
    }

    
    /**
     * This service accepts userId for validation and returns RBAC session.  This service will not check the password nor perform password policy validations.<br />
     * The successful result is {@link org.apache.directory.fortress.core.model.Session} that contains target user's RBAC {@link org.apache.directory.fortress.core.model.User#roles} and Admin role {@link org.apache.directory.fortress.core.model.User#adminRoles}.<br />
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the names of assigned RBAC roles targeted for activation into Session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains the names of assigned ARBAC roles targeted for activation into Session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected on behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     * </ul>
     * </ul>
     * <h4> This API will...</h4>
     * <ul>
     * <li> fail for any user who is locked by OpenLDAP's policies {@link org.apache.directory.fortress.core.model.User#isLocked()}.
     * <li> evaluate temporal {@link org.apache.directory.fortress.core.util.time.Constraint}(s) on {@link org.apache.directory.fortress.core.model.User}, {@link org.apache.directory.fortress.core.model.UserRole} and {@link org.apache.directory.fortress.core.model.UserAdminRole} entities.
     * <li> process selective role activations into User RBAC Session {@link org.apache.directory.fortress.core.model.User#roles}.
     * <li> check Dynamic Separation of Duties {@link org.apache.directory.fortress.core.model.DSDChecker#validate(org.apache.directory.fortress.core.model.Session, org.apache.directory.fortress.core.util.time.Constraint, org.apache.directory.fortress.core.util.time.Time)} on {@link org.apache.directory.fortress.core.model.User#roles}.
     * <li> process selective administrative role activations {@link org.apache.directory.fortress.core.model.User#adminRoles}.
     * <li> return a {@link org.apache.directory.fortress.core.model.Session} containing {@link org.apache.directory.fortress.core.model.Session#getUser()}, {@link org.apache.directory.fortress.core.model.Session#getRoles()} and (if admin user) {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()} if everything checks out good.
     * <li> return a checked exception that will be {@link org.apache.directory.fortress.core.SecurityException} or its derivation.
     * <li> return a {@link org.apache.directory.fortress.core.SecurityException} for system failures.
     * <li> return a {@link org.apache.directory.fortress.core.ValidationException} for data validation errors.
     * <li> return a {@link org.apache.directory.fortress.core.FinderException} if User id not found.
     * <li> (optionally) store parms passed in by client for audit trail purposes.
     * </ul>
     * <h4>
     * The function is valid if and only if:
     * </h4>
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the (optional) active role set is a subset of the roles authorized for that user.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result code {@link org.apache.directory.fortress.core.model.Session#errorId}, RBAC role activations {@link org.apache.directory.fortress.core.model.Session#getRoles()}, Admin Role activations {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()},OpenLDAP pw policy codes {@link org.apache.directory.fortress.core.model.Session#getWarnings()}}, {@link org.apache.directory.fortress.core.model.Session#expirationSeconds}, {@link org.apache.directory.fortress.core.model.Session#graceLogins} and more.
     */
    @POST
    @Path("/" + HttpIds.RBAC_CREATE_TRUSTED + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse createSessionTrusted( FortRequest request )
    {
        return accessMgrImpl.createSessionTrusted( request );
    }

    
    /**
     * Perform user RBAC authorization.  This function returns a Boolean value meaning whether the subject of a given session is
     * allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.RBAC_AUTHZ + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse checkAccess( FortRequest request )
    {
        return accessMgrImpl.checkAccess( request );
    }

    
    /**
     * This function returns the permissions of the session, i.e., the permissions assigned
     * to its authorized roles. The function is valid if and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link org.apache.directory.fortress.core.model.Permission}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.RBAC_PERMS + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse sessionPermissions( FortRequest request )
    {
        return accessMgrImpl.sessionPermissions( request );
    }

    
    /**
     * This function returns the active roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link org.apache.directory.fortress.core.model.UserRole}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.RBAC_ROLES + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse sessionRoles( FortRequest request )
    {
        return accessMgrImpl.sessionRoles( request );
    }

    
    /**
     * This function returns the authorized roles associated with a session based on hierarchical relationships. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String containing role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.RBAC_AUTHZ_ROLES + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse authorizedSessionRoles( FortRequest request )
    {
        return accessMgrImpl.authorizedSessionRoles( request );
    }

    
    /**
     * This function adds a role as an active role of a session whose owner is a given user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for activation into User's session</li>
     * </ul>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the role is a member of the ROLES data set
     * <li> the role inclusion does not violate Dynamic Separation of Duty Relationships
     * <li> the session is a valid Fortress session
     * <li> the user is authorized to that role
     * <li> the session is owned by that user.
     * </ul>
     * </p>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    @POST
    @Path("/" + HttpIds.RBAC_ADD + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse addActiveRole( FortRequest request )
    {
        return accessMgrImpl.addActiveRole( request );
    }

    
    /**
     * This function deletes a role from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the role is an active role of that session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for removal from User's session</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    @POST
    @Path("/" + HttpIds.RBAC_DROP + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse dropActiveRole( FortRequest request )
    {
        return accessMgrImpl.dropActiveRole( request );
    }

    
    /**
     * This function returns the userId value that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to {@link org.apache.directory.fortress.core.model.User#userId} only.
     */
    @POST
    @Path("/" + HttpIds.RBAC_USERID + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse getUserId( FortRequest request )
    {
        return accessMgrImpl.getUserId( request );
    }

    
    /**
     * This function returns the user object that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to {@link org.apache.directory.fortress.core.model.User}.
     */
    @POST
    @Path("/" + HttpIds.RBAC_USER + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse getUser( FortRequest request )
    {
        return accessMgrImpl.getUser( request );
    }


    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDADMINMGR
     * **************************************************************************************************************************************
     */
    /**
     * This command creates a new admin role. The command is valid if and only if the new admin role is not
     * already a member of the ADMIN ROLES data set. The ADMIN ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} object</li>
     *   <h5>AdminRole required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole being targeted for addition to LDAP</li>
     *   </ul>
     *   <h5>AdminRole optional parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#description} - contains any safe text</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#osPs} * - multi-occurring attribute used to set associations to existing PERMS OrgUnits</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#osUs} * - multi-occurring attribute used to set associations to existing USERS OrgUnits</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginRange} - contains the name of an existing RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole activated) controls</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#endRange} - contains the name of an existing RBAC Role that represents that highest role in hierarchy that administrator may control</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginInclusive} - if 'true' the RBAC Role specified in beginRange is also controlled by the posessor of this AdminRole</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#endInclusive} - if 'true' the RBAC Role specified in endRange is also controlled by the administratrator</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginTime} - HHMM - determines begin hour adminRole may be activated into user's ARBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#endTime} - HHMM - determines end hour adminRole may be activated into user's ARBAC session.</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginDate} - YYYYMMDD - determines date when adminRole may be activated into user's ARBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#endDate} - YYYYMMDD - indicates latest date adminRole may be activated into user's ARBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    @POST
    @Path("/" + HttpIds.ARLE_ADD + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addAdminRole( FortRequest request )
    {
        return delegatedAdminMgrImpl.addAdminRole( request );
    }

    
    /**
     * This command deletes an existing admin role from the ARBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ADMIN ROLES data set.  This command will
     * also deassign role from all users.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} object</li>
     * <h5>AdminRole required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole being targeted for removal from LDAP</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    @POST
    @Path("/" + HttpIds.ARLE_DELETE + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse deleteAdminRole( FortRequest request )
    {
        return delegatedAdminMgrImpl.deleteAdminRole( request );
    }

    
    /**
     * Method will update an AdminRole entity in the directory.  The role must exist in directory prior to this call.     *
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} object</li>
     * <h5>AdminRole required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole being targeted for update to LDAP</li>
     * </ul>
     * <h5>AdminRole optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#description} - contains any safe text</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#osPs} * - multi-occurring attribute used to set associations to existing PERMS OrgUnits</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#osUs} * - multi-occurring attribute used to set associations to existing USERS OrgUnits</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginRange} - contains the name of an existing RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole activated) controls</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#endRange} - contains the name of an existing RBAC Role that represents that highest role in hierarchy that administrator may control</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginInclusive} - if 'true' the RBAC Role specified in beginRange is also controlled by the posessor of this AdminRole</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#endInclusive} - if 'true' the RBAC Role specified in endRange is also controlled by the administratrator</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginTime} - HHMM - determines begin hour adminRole may be activated into user's ARBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#endTime} - HHMM - determines end hour adminRole may be activated into user's ARBAC session.</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginDate} - YYYYMMDD - determines date when adminRole may be activated into user's ARBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#endDate} - YYYYMMDD - indicates latest date adminRole may be activated into user's ARBAC session</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    @POST
    @Path("/" + HttpIds.ARLE_UPDATE + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse updateAdminRole( FortRequest request )
    {
        return delegatedAdminMgrImpl.updateAdminRole( request );
    }

    
    /**
     * This command assigns a user to an administrative role.
     * <ul>
     *   <li> The command is valid if and only if:
     *   <li> The user is a member of the USERS data set
     *   <li> The role is a member of the ADMIN ROLES data set
     *   <li> The user is not already assigned to the admin role
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} object</li>
     *   <h5>UserAdminRole required parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the name for already existing AdminRole to be assigned</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#userId} - contains the userId for existing User</li>
     *   </ul>
     *   <h5>UserAdminRole optional parameters</h5>
     *   <ul>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#beginTime} - HHMM - determines begin hour AdminRole may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#endTime} - HHMM - determines end hour AdminRole may be activated into user's RBAC session.</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#beginDate} - YYYYMMDD - determines date when AdminRole may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#endDate} - YYYYMMDD - indicates latest date AdminRole may be activated into user's RBAC session</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     *     <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     *   </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * <p>
     * Successful completion of this op, the following occurs:
     * <ul>
     *   <li> User entity (resides in people container) has role assignment added to aux object class attached to actual user record.
     *   <li> AdminRole entity (resides in adminRole container) has userId added as role occupant.
     *   <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:
     *   <ul>
     *     <li> timeout - number in seconds of session inactivity time allowed.
     *     <li> beginDate - YYYYMMDD - determines date when role may be activated.
     *     <li> endDate - YYMMDD - indicates latest date role may be activated.
     *     <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status
     *     <li> endLockDate - YYMMDD - determines end of enforced inactive status.
     *     <li> beginTime - HHMM - determines begin hour role may be activated in user's session.
     *     <li> endTime - HHMM - determines end hour role may be activated in user's session.*
     *     <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.
     *   </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_ASGN + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse assignAdminUser( FortRequest request )
    {
        return delegatedAdminMgrImpl.assignAdminUser( request );
    }

    
    /**
     * This method removes assigned admin role from user entity.  Both user and admin role entities must exist and have role relationship
     * before calling this method.
     * Successful completion:
     * del Role to User assignment in User data set
     * AND
     * User to Role assignment in Admin Role data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} object</li>
     * <h5>UserAdminRole required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the name for already existing AdminRole to be deassigned</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#userId} - contains the userId for existing User</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_DEASGN + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse deassignAdminUser( FortRequest request )
    {
        return delegatedAdminMgrImpl.deassignAdminUser( request );
    }

    
    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole. The command is valid if and only if childRole is not a member of the ADMINROLES data set,
     * and parentRole is a member of the ADMINROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing parent role</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of new child role</li>
     * </ul>
     * <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#description} - maps to description attribute on organizationalRole object class for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new child</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The childRole is not a member of the ADMINROLES data set.
     * <li> The parentRole is a member of the ADMINROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new adminRole.
     * <li> Assigns role relationship between new childRole and pre-existing parentRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_DESC + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addAdminDescendant( FortRequest request )
    {
        return delegatedAdminMgrImpl.addAdminDescendant( request );
    }

    
    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole. The command is valid if and only if parentRole is not a member of the ADMINROLES data set,
     * and childRole is a member of the ADMINROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>childRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing child AdminRole</li>
     * <li>parentRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of new AdminRole to be parent</li>
     * </ul>
     * <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#description} - maps to description attribute on organizationalRole object class for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole is not a member of the ADMINROLES data set.
     * <li> The childRole is a member of the ADMINROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new adminRole.
     * <li> Assigns role relationship between new parentRole and pre-existing childRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_ASC + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addAdminAscendant( FortRequest request )
    {
        return delegatedAdminMgrImpl.addAdminAscendant( request );
    }

    
    /**
     * This commands establishes a new immediate inheritance relationship parentRole <<-- childRole between existing
     * roles parentRole, childRole. The command is valid if and only if parentRole and childRole are members of the ADMINROLES data
     * set, parentRole is not an immediate ascendant of childRole, and childRole does not properly inherit parentRole (in order to
     * avoid cycle creation).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing AdminRole to be parent</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing AdminRole to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole and childRole are members of the ADMINROLES data set.
     * <li> The parentRole is not an immediate ascendant of childRole.
     * <li> The childRole does not properly inherit parentRole (in order to avoid cycle creation).
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_ADDINHERIT + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addAdminInheritance( FortRequest request )
    {
        return delegatedAdminMgrImpl.addAdminInheritance( request );
    }

    
    /**
     * This command deletes an existing immediate inheritance relationship parentRole <<-- childRole. The command is
     * valid if and only if the adminRoles parentRole and childRole are members of the ADMINROLES data set, and parentRole is an
     * immediate ascendant of childRole. The new inheritance relation is computed as the reflexive-transitive
     * closure of the immediate inheritance relation resulted after deleting the relationship parentRole <<-- childRole.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing Role to remove parent relationship</li>
     * <li>{@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing Role to remove child relationship</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The roles parentRole and childRole are members of the ADMINROLES data set.
     * <li> The parentRole is an immediate ascendant of childRole.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parentRole <<-- childRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ARLE_DELINHERIT + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse deleteAdminInheritance( FortRequest request )
    {
        return delegatedAdminMgrImpl.deleteAdminInheritance( request );
    }

    
    /**
     * Commands adds a new OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of new USERS or PERMS OrgUnit to be added</li>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * </ul>
     * <h5>OrgUnit optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_ADD + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addOrg( FortRequest request )
    {
        return delegatedAdminMgrImpl.addOrg( request );
    }

    
    /**
     * Commands updates existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of USERS or PERMS OrgUnit to be updated</li>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * </ul>
     * <h5>OrgUnit optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_UPDATE + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse updateOrg( FortRequest request )
    {
        return delegatedAdminMgrImpl.updateOrg( request );
    }

    
    /**
     * Commands deletes existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of USERS or PERMS OrgUnit to be removed</li>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_DELETE + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse deleteOrg( FortRequest request )
    {
        return delegatedAdminMgrImpl.deleteOrg( request );
    }

    
    /**
     * This commands creates a new orgunit child, and inserts it in the orgunit hierarchy as an immediate descendant of
     * the existing orgunit parent.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to be parent</li>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to be child</li>
     * </ul>
     * <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     * <ul>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#description} - maps to description attribute on organizationalUnit object class for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The child orgunit is not a member of the ORGUNITS data set.
     * <li> The parent orgunit is a member of the ORGUNITS data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new orgunit.
     * <li> Assigns orgunit relationship between new child and pre-existing parent.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_DESC + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addOrgDescendant( FortRequest request )
    {
        return delegatedAdminMgrImpl.addOrgDescendant( request );
    }

    
    /**
     * This commands creates a new orgunit parent, and inserts it in the orgunit hierarchy as an immediate ascendant of
     * the existing child orgunit.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the name of existing OrgUnit to be child</li>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#type} - contains the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the name of new OrgUnit to be parent</li>
     * </ul>
     * <h5>optional parameters {@code org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     * <ul>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#description} - maps to description attribute on organizationalUnit object class for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parent is not a member of the ORGUNITS data set.
     * <li> The child is a member of the ORGUNITS data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new orgunit.
     * <li> Assigns orgunit relationship between new parent and pre-existing child.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_ASC + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addOrgAscendant( FortRequest request )
    {
        return delegatedAdminMgrImpl.addOrgAscendant( request );
    }

    
    /**
     * This commands establishes a new immediate inheritance relationship with parent orgunit <<-- child orgunit
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to be parent</li>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parent and child are members of the ORGUNITS data set.
     * <li> The parent is not an immediate ascendant of child.
     * <li> The child does not properly inherit parent (in order to avoid cycle creation).
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_ADDINHERIT + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse addOrgInheritance( FortRequest request )
    {
        return delegatedAdminMgrImpl.addOrgInheritance( request );
    }

    
    /**
     * This command deletes an existing immediate inheritance relationship parent <<-- child.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to remove as parent</li>
     * <li>parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * <li>child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to remove as child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The orgunits parent and child are members of the ORGUNITS data set.
     * <li> The parent is an immediate ascendant of child.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parent <<-- child.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.ORG_DELINHERIT + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ADMIN_MGR_USER})
    @Override
    public FortResponse deleteOrgInheritance( FortRequest request )
    {
        return delegatedAdminMgrImpl.deleteOrgInheritance( request );
    }


    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDREVIEWMGR
     * **************************************************************************************************************************************
     */
    /**
     * Method reads Admin Role entity from the admin role container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.AdminRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the AdminRole being targeted for read</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole}
     */
    @POST
    @Path("/" + HttpIds.ARLE_READ + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse readAdminRole( FortRequest request )
    {
        return delegatedReviewMgrImpl.readAdminRole( request );
    }

    
    /**
     * Method will return a list of type AdminRole matching all or part of {@link org.apache.directory.fortress.core.model.AdminRole#name}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains all or some of the chars corresponding to adminRole entities stored in directory.</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.AdminRole}
     */
    @POST
    @Path("/" + HttpIds.ARLE_SEARCH + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse findAdminRoles( FortRequest request )
    {
        return delegatedReviewMgrImpl.findAdminRoles( request );
    }

    
    /**
     * This function returns the set of adminRoles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.UserAdminRole}
     */
    @POST
    @Path("/" + HttpIds.ARLE_ASGNED + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse assignedAdminRoles( FortRequest request )
    {
        return delegatedReviewMgrImpl.assignedAdminRoles( request );
    }

    
    /**
     * This method returns the data set of all users who are assigned the given admin role.  This searches the User data set for
     * AdminRole relationship.  This method does NOT search for hierarchical AdminRoles relationships.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.AdminRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name to use for the AdminRole targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.User}
     */
    @POST
    @Path("/" + HttpIds.USER_ASGNED_ADMIN + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse assignedAdminUsers( FortRequest request )
    {
        return delegatedReviewMgrImpl.assignedAdminUsers( request );
    }

    
    /**
     * Commands reads existing OrgUnit entity from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.OrgUnit} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name associated with the OrgUnit object targeted for search.</li>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit}
     */
    @POST
    @Path("/" + HttpIds.ORG_READ + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse readOrg( FortRequest request )
    {
        return delegatedReviewMgrImpl.readOrg( request );
    }

    
    /**
     * Commands searches existing OrgUnit entities from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type parameter on API.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.OrgUnit} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains some or all of the chars associated with the OrgUnit objects targeted for search.</li>
     * <li>{@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link org.apache.directory.fortress.core.model.OrgUnit}
     */
    @POST
    @Path("/" + HttpIds.ORG_SEARCH + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_REVIEW_MGR_USER})
    @Override
    public FortResponse searchOrg( FortRequest request )
    {
        return delegatedReviewMgrImpl.searchOrg( request );
    }

    
    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDACCESSMGR
     * **************************************************************************************************************************************
     */
    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-assign URA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId targeted for operation</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_ASSIGN + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse canAssign( FortRequest request )
    {
        return delegatedAccessMgrImpl.canAssign( request );
    }

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-revoke URA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId targeted for operation</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_DEASSIGN + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse canDeassign( FortRequest request )
    {
        return delegatedAccessMgrImpl.canDeassign( request );
    }

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-assign-p PRA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RolePerm} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.RolePerm} required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#perm#objName} - contains the permission object name targeted for operation</li>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#perm#opName} - contains the permission operation name targeted</li>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#role#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_GRANT + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse canGrant( FortRequest request )
    {
        return delegatedAccessMgrImpl.canGrant( request );
    }

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-revoke-p PRA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RolePerm} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.RolePerm} required parameters</h5>
     * <ul>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#perm#objName} - contains the permission object name targeted for operation</li>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#perm#opName} - contains the permission operation name targeted</li>
     * <li>{@code org.apache.directory.fortress.core.model.RolePerm#role#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_REVOKE + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse canRevoke( FortRequest request )
    {
        return delegatedAccessMgrImpl.canRevoke( request );
    }

    
    /**
     * This function returns a Boolean value meaning whether the subject of a given session is
     * allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to admin {@link org.apache.directory.fortress.core.model.Permission} entity</li>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing admin object being targeted</li>
     * <li>{@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing admin permission operation</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_AUTHZ + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse checkAdminAccess( FortRequest request )
    {
        return delegatedAccessMgrImpl.checkAdminAccess( request );
    }

    
    /**
     * This function adds an AdminRole as an active role of a session whose owner is a given user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAdminRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAdminRole} - contains the AdminRole name targeted for activation into User's session</li>
     * </ul>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the AdminRole is a member of the ADMINROLES data set
     * <li> the session is a valid Fortress session
     * <li> the user is authorized to that AdminRole
     * <li> the session is owned by that user.
     * </ul>
     * </p>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_ADD + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse addActiveAdminRole( FortRequest request )
    {
        return delegatedAccessMgrImpl.addActiveAdminRole( request );
    }

    
    /**
     * This function deletes an AdminRole from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the AdminRole is an active role of that session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} entity.</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the AdminRole name targeted for removal from User's session</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_DROP + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse dropActiveAdminRole( FortRequest request )
    {
        return delegatedAccessMgrImpl.dropActiveAdminRole( request );
    }

    
    /**
     * This function returns the active admin roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link org.apache.directory.fortress.core.model.UserAdminRole}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_ROLES + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse sessionAdminRoles( FortRequest request )
    {
        return delegatedAccessMgrImpl.sessionAdminRoles( request );
    }

    
    /**
     * This function returns the ARBAC (administrative) permissions of the session, i.e., the admin permissions assigned
     * to its authorized admin roles. The function is valid if and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link org.apache.directory.fortress.core.model.Permission}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_PERMS + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse sessionAdminPermissions( FortRequest request )
    {
        return delegatedAccessMgrImpl.sessionAdminPermissions( request );
    }

    
    /**
     * This function returns the authorized ARBAC (administrative) roles associated with a session based on hierarchical relationships. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String containing role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    @POST
    @Path("/" + HttpIds.ADMIN_AUTHZ_ROLES + "/")
    @RolesAllowed({SUPER_USER, DELEGATED_ACCESS_MGR_USER})
    @Override
    public FortResponse authorizedSessionAdminRoles( FortRequest request )
    {
        return delegatedAccessMgrImpl.authorizedSessionRoles( request );
    }


    /**
     * ************************************************************************************************************************************
     * BEGIN PSWDPOLICYMGR
     * **************************************************************************************************************************************
     */
    /**
     * This method will add a new policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is not already present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} object</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being added.</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#minAge} - This attribute holds the number of seconds that must elapse between
     * modifications to the password.  If this attribute is not present, 0
     * seconds is assumed.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#maxAge} - This attribute holds the number of seconds after which a modified
     * password will expire. If this attribute is not present, or if the value is 0 the password
     * does not expire.  If not 0, the value must be greater than or equal
     * to the value of the pwdMinAge.
     * </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#inHistory} - This attribute specifies the maximum number of used passwords stored
     * in the pwdHistory attribute. If this attribute is not present, or if the value is 0, used
     * passwords are not stored in the pwdHistory attribute and thus may be reused.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#minLength} - When quality checking is enabled, this attribute holds the minimum
     * number of characters that must be used in a password.  If this
     * attribute is not present, no minimum password length will be
     * enforced.  If the server is unable to check the length (due to a
     * hashed password or otherwise), the server will, depending on the
     * value of the pwdCheckQuality attribute, either accept the password
     * without checking it ('0' or '1') or refuse it ('2').</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#expireWarning} - This attribute specifies the maximum number of seconds before a
     * password is due to expire that expiration warning messages will be
     * returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     * will be returned.  If not 0, the value must be smaller than the value
     * of the pwdMaxAge attribute.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#graceLoginLimit} - This attribute specifies the number of times an expired password can
     * be used to authenticate.  If this attribute is not present or if the
     * value is 0, authentication will fail. </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#lockout} - This attribute indicates, when its value is "TRUE", that the password
     * may not be used to authenticate after a specified number of
     * consecutive failed bind attempts.  The maximum number of consecutive
     * failed bind attempts is specified in pwdMaxFailure.  If this attribute is not present, or if the
     * value is "FALSE", the password may be used to authenticate when the number of failed bind
     * attempts has been reached.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#lockoutDuration} - This attribute holds the number of seconds that the password cannot
     * be used to authenticate due to too many failed bind attempts.  If
     * this attribute is not present, or if the value is 0 the password
     * cannot be used to authenticate until reset by a password
     * administrator.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#maxFailure} - This attribute specifies the number of consecutive failed bind
     * attempts after which the password may not be used to authenticate.
     * If this attribute is not present, or if the value is 0, this policy
     * is not checked, and the value of pwdLockout will be ignored.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#failureCountInterval} - This attribute holds the number of seconds after which the password
     * failures are purged from the failure counter, even though no
     * successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     * counter is only reset by a successful authentication.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#mustChange} - This attribute specifies with a value of "TRUE" that users must
     * change their passwords when they first bind to the directory after a
     * password is set or reset by a password administrator.  If this
     * attribute is not present, or if the value is "FALSE", users are not
     * required to change their password upon binding after the password
     * administrator sets or resets the password.  This attribute is not set
     * due to any actions specified by this document, it is typically set by
     * a password administrator after resetting a user's password.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#allowUserChange} - This attribute indicates whether users can change their own
     * passwords, although the change operation is still subject to access
     * control.  If this attribute is not present, a value of "TRUE" is
     * assumed.  This attribute is intended to be used in the absence of an access control mechanism.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#safeModify} - This attribute specifies whether or not the existing password must be
     * sent along with the new password when being changed.  If this
     * attribute is not present, a "FALSE" value is assumed.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#checkQuality} - This attribute indicates how the password quality will be verified
     * while being modified or added.  If this attribute is not present, or
     * if the value is '0', quality checking will not be enforced.  A value
     * of '1' indicates that the server will check the quality, and if the
     * server is unable to check it (due to a hashed password or other
     * reasons) it will be accepted.  A value of '2' indicates that the
     * server will check the quality, and if the server is unable to verify
     * it, it will return an error refusing the password. </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#attribute} - This holds the name of the attribute to which the password policy is
     * applied.  For example, the password policy may be applied to the
     * userPassword attribute </li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PSWD_ADD + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse addPolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.addPolicy( request );
    }

    
    /**
     * This method will update an exiting policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} object</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being updated.</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#minAge} - This attribute holds the number of seconds that must elapse between
     * modifications to the password.  If this attribute is not present, 0
     * seconds is assumed.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#maxAge} - This attribute holds the number of seconds after which a modified
     * password will expire. If this attribute is not present, or if the value is 0 the password
     * does not expire.  If not 0, the value must be greater than or equal
     * to the value of the pwdMinAge.
     * </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#inHistory} - This attribute specifies the maximum number of used passwords stored
     * in the pwdHistory attribute. If this attribute is not present, or if the value is 0, used
     * passwords are not stored in the pwdHistory attribute and thus may be reused.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#minLength} - When quality checking is enabled, this attribute holds the minimum
     * number of characters that must be used in a password.  If this
     * attribute is not present, no minimum password length will be
     * enforced.  If the server is unable to check the length (due to a
     * hashed password or otherwise), the server will, depending on the
     * value of the pwdCheckQuality attribute, either accept the password
     * without checking it ('0' or '1') or refuse it ('2').</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#expireWarning} - This attribute specifies the maximum number of seconds before a
     * password is due to expire that expiration warning messages will be
     * returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     * will be returned.  If not 0, the value must be smaller than the value
     * of the pwdMaxAge attribute.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#graceLoginLimit} - This attribute specifies the number of times an expired password can
     * be used to authenticate.  If this attribute is not present or if the
     * value is 0, authentication will fail. </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#lockout} - This attribute indicates, when its value is "TRUE", that the password
     * may not be used to authenticate after a specified number of
     * consecutive failed bind attempts.  The maximum number of consecutive
     * failed bind attempts is specified in pwdMaxFailure.  If this attribute is not present, or if the
     * value is "FALSE", the password may be used to authenticate when the number of failed bind
     * attempts has been reached.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#lockoutDuration} - This attribute holds the number of seconds that the password cannot
     * be used to authenticate due to too many failed bind attempts.  If
     * this attribute is not present, or if the value is 0 the password
     * cannot be used to authenticate until reset by a password
     * administrator.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#maxFailure} - This attribute specifies the number of consecutive failed bind
     * attempts after which the password may not be used to authenticate.
     * If this attribute is not present, or if the value is 0, this policy
     * is not checked, and the value of pwdLockout will be ignored.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#failureCountInterval} - This attribute holds the number of seconds after which the password
     * failures are purged from the failure counter, even though no
     * successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     * counter is only reset by a successful authentication.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#mustChange} - This attribute specifies with a value of "TRUE" that users must
     * change their passwords when they first bind to the directory after a
     * password is set or reset by a password administrator.  If this
     * attribute is not present, or if the value is "FALSE", users are not
     * required to change their password upon binding after the password
     * administrator sets or resets the password.  This attribute is not set
     * due to any actions specified by this document, it is typically set by
     * a password administrator after resetting a user's password.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#allowUserChange} - This attribute indicates whether users can change their own
     * passwords, although the change operation is still subject to access
     * control.  If this attribute is not present, a value of "TRUE" is
     * assumed.  This attribute is intended to be used in the absence of an access control mechanism.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#safeModify} - This attribute specifies whether or not the existing password must be
     * sent along with the new password when being changed.  If this
     * attribute is not present, a "FALSE" value is assumed.</li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#checkQuality} - This attribute indicates how the password quality will be verified
     * while being modified or added.  If this attribute is not present, or
     * if the value is '0', quality checking will not be enforced.  A value
     * of '1' indicates that the server will check the quality, and if the
     * server is unable to check it (due to a hashed password or other
     * reasons) it will be accepted.  A value of '2' indicates that the
     * server will check the quality, and if the server is unable to verify
     * it, it will return an error refusing the password. </li>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#attribute} - This holds the name of the attribute to which the password policy is
     * applied.  For example, the password policy may be applied to the
     * userPassword attribute </li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PSWD_UPDATE + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse updatePolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.updatePolicy( request );
    }

    
    /**
     * This method will delete exiting policy entry from the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.  Existing users that
     * are assigned this policy will be removed from association.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} object</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being removed.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PSWD_DELETE + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse deletePolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.deletePolicy( request );
    }

    
    /**
     * This method will return the password policy entity to the caller.  This command is valid
     * if and only if the policy entry is present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy}
     */
    @POST
    @Path("/" + HttpIds.PSWD_READ + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse readPolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.readPolicy( request );
    }

    
    /**
     * This method will return a list of all password policy entities that match a particular search string.
     * This command will return an empty list of no matching entries are found.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.PwPolicy}
     */
    @POST
    @Path("/" + HttpIds.PSWD_SEARCH + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse searchPolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.searchPolicy( request );
    }

    
    /**
     * This method will associate a user entity with a password policy entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policyName refers to a
     * policy that is a member of the PWPOLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the userId targeted for update</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} object</li>
     * <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy object class targeted for assignment.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PSWD_USER_ADD + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse updateUserPolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.updateUserPolicy( request );
    }

    
    /**
     * This method will remove the pw policy assignment from a user entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policy attribute is assigned.
     * Removal of pw policy assignment will revert the user's policy to use the global default for OpenLDAP
     * instance that contains user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the userId targeted for removal of policy assignment</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.PSWD_USER_DELETE + "/")
    @RolesAllowed({SUPER_USER, PASSWORD_MGR_USER})
    @Override
    public FortResponse deleteUserPolicy( FortRequest request )
    {
        return pswdPolicyMgrImpl.deleteUserPolicy( request );
    }

    
    /**
     * ************************************************************************************************************************************
     * BEGIN AUDIT
     * **************************************************************************************************************************************
     */
    /**
     * This method returns a list of authentication audit events for a particular user {@link org.apache.directory.fortress.core.model.UserAudit#userId},
     * and given timestamp field {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId<</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.Bind}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_BINDS + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse searchBinds( FortRequest request )
    {
        return auditMgrImpl.searchBinds( request );
    }

    
    /**
     * This method returns a list of authorization events for a particular user {@link org.apache.directory.fortress.core.model.UserAudit#userId}
     * and given timestamp field {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.
     * Method also can discriminate between all events or failed only by setting {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_UAUTHZS + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse getUserAuthZs( FortRequest request )
    {
        return auditMgrImpl.getUserAuthZs( request );
    }

    
    /**
     * This method returns a list of authorization events for a particular user {@link org.apache.directory.fortress.core.model.UserAudit#userId},
     * object {@link org.apache.directory.fortress.core.model.UserAudit#objName}, and given timestamp field {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * Method also can discriminate between all events or failed only by setting flag {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly}..
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId<</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#objName} - contains the object (authorization resource) name</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_AUTHZS + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse searchAuthZs( FortRequest request )
    {
        return auditMgrImpl.searchAuthZs( request );
    }

    
    /**
     * This method returns a list of sessions created for a given user {@link org.apache.directory.fortress.core.model.UserAudit#userId},
     * and timestamp {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} required parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId<</li>
     * </ul>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to begin search</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.Mod}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_SESSIONS + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse searchUserSessions( FortRequest request )
    {
        return auditMgrImpl.searchUserSessions( request );
    }

    
    /**
     * This method returns a list of admin operations events for a particular entity {@link org.apache.directory.fortress.core.model.UserAudit#dn},
     * object {@link org.apache.directory.fortress.core.model.UserAudit#objName} and timestamp {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.  If the internal
     * userId {@link org.apache.directory.fortress.core.model.UserAudit#internalUserId} is set it will limit search by that field.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#dn} - contains the LDAP distinguished name for the updated object.  For example if caller
     * wants to find out what changes were made to John Doe's user object this would be 'uid=jdoe,ou=People,dc=example,dc=com'</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#objName} - contains the object (authorization resource) name corresponding to the event.  For example if caller
     * wants to return events where User object was modified, this would be 'updateUser'</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#internalUserId} - maps to the internalUserId of user who changed the record in LDAP.  This maps to {@link org.apache.directory.fortress.core.model.User#internalId}.</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#endDate} - contains the date in which to end search</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.Mod}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_MODS + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse searchAdminMods( FortRequest request )
    {
        return auditMgrImpl.searchAdminMods( request );
    }

    
    /**
     * This method returns a list of failed authentication attempts on behalf of an invalid identity {@link org.apache.directory.fortress.core.model.UserAudit#userId},
     * and given timestamp {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.  If the {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} is true it will
     * return only authentication attempts made with invalid userId.  This event represents either User incorrectly entering userId during signon or
     * possible fraudulent logon attempt by hostile agent.
     * </p>
     * This event is generated when Fortress looks up User record prior to LDAP bind operation.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} entity</li>
     * <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     * <ul>
      * <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    @POST
    @Path("/" + HttpIds.AUDIT_INVLD + "/")
    @RolesAllowed({SUPER_USER, AUDIT_MGR_USER})
    @Override
    public FortResponse searchInvalidUsers( FortRequest request )
    {
        return auditMgrImpl.searchInvalidUsers( request );
    }

    
    /**
     * ************************************************************************************************************************************
     * BEGIN CONFIGMGR
     * **************************************************************************************************************************************
     */
    /**
     * Create a new configuration node with given name and properties.  The name is required.  If node already exists,
     * a {@link org.apache.directory.fortress.core.SecurityException} with error {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_ALREADY_EXISTS} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props} object</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.CFG_ADD + "/")
    @RolesAllowed({SUPER_USER, CONFIG_MGR_USER})
    @Override
    public FortResponse addConfig( FortRequest request )
    {
        return configMgrImpl.addConfig( request );
    }

    
    /**
     * Update existing configuration node with additional properties, or, replace existing properties.  The name is required.  If node does not exist,
     * a {@link org.apache.directory.fortress.core.SecurityException} with error {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for update</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props} object</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.CFG_UPDATE + "/")
    @RolesAllowed({SUPER_USER, CONFIG_MGR_USER})
    @Override
    public FortResponse updateConfig( FortRequest request )
    {
        return configMgrImpl.updateConfig( request );
    }

    
    /**
     * This service will either completely remove named configuration node from the directory or specified properties depending on the arguments passed in.
     * <p style="font-size:1em; color:red;">
     * If properties are not passed in along with the name, this method will remove the configuration node completely from directory.<BR>
     * Care should be taken during execution to ensure target name is correct and permanent removal of all parameters located
     * there is intended.  There is no 'undo' for this operation.
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for removal</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props} object. If this argument is passed service will remove only the properties listed</li>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    @POST
    @Path("/" + HttpIds.CFG_DELETE + "/")
    @RolesAllowed({SUPER_USER, CONFIG_MGR_USER})
    @Override
    public FortResponse deleteConfig( FortRequest request )
    {
        return configMgrImpl.deleteConfig( request );
    }

    
    /**
     * Read an existing configuration node with given name and return to caller.  The name is required.  If node doesn't exist,
     * a {@link org.apache.directory.fortress.core.SecurityException} with error {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link org.apache.directory.fortress.core.model.Props}
     */
    @POST
    @Path("/" + HttpIds.CFG_READ + "/")
    @RolesAllowed({SUPER_USER, CONFIG_MGR_USER})
    @Override
    public FortResponse readConfig( FortRequest request )
    {
        return configMgrImpl.readConfig( request );
    }
}