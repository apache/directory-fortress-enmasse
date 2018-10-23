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
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.rest.HttpIds;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;

/**
 * Implementation for Fortress Rest Service methods forwards to delegate.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Service("fortressService")
public class FortressServiceImpl implements FortressService
{
    private static final Logger log = Logger.getLogger( FortressServiceImpl.class.getName() );
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
    private final GroupMgrImpl groupMgrImpl = new GroupMgrImpl();

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

    @Context
    private HttpServletRequest httpRequest;

    /**
     * ************************************************************************************************************************************
     * BEGIN ADMINMGR
     * **************************************************************************************************************************************
     */

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_GRANT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse grant( FortRequest request )
    {
        return adminMgrImpl.grant( request, this );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_REVOKE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse revoke( FortRequest request )
    {
        return adminMgrImpl.revoke( request, this );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_GRANT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse grantUser( FortRequest request )
    {
        return adminMgrImpl.grantUser( request, this );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_REVOKE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse revokeUser( FortRequest request )
    {
        return adminMgrImpl.revokeUser( request, this );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ADD_CONSTRAINT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addRoleConstraint( FortRequest request )
    {
        return adminMgrImpl.addRoleConstraint( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DELETE_CONSTRAINT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse removeRoleConstraint( FortRequest request )
    {
        return adminMgrImpl.removeRoleConstraint( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DELETE_CONSTRAINT_ID + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse removeRoleConstraintWid( FortRequest request )
    {
        return adminMgrImpl.removeRoleConstraintWid( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_ADD_ATTRIBUTE_SET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addPermissionAttributeSet( FortRequest request )
    {
        return adminMgrImpl.addPermissionAttributeSet( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_DELETE_ATTRIBUTE_SET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deletePermissionAttributeSet( FortRequest request )
    {
        return adminMgrImpl.deletePermissionAttributeSet( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_ADD_PERM_ATTRIBUTE_TO_SET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addPermissionAttributeToSet( FortRequest request )
    {
        return adminMgrImpl.addPermissionAttributeToSet( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_DELETE_PERM_ATTRIBUTE_TO_SET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse removePermissionAttributeFromSet( FortRequest request )
    {
        return adminMgrImpl.removePermissionAttributeFromSet( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_UPDATE_PERM_ATTRIBUTE_IN_SET + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updatePermissionAttributeInSet( FortRequest request )
    {
        return adminMgrImpl.updatePermissionAttributeInSet( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_ENABLE_CONSTRAINT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse enableRoleConstraint( FortRequest request )
    {
        return adminMgrImpl.enableRoleConstraint( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_DISABLE_CONSTRAINT + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse disableRoleConstraint( FortRequest request )
    {
        return adminMgrImpl.disableRoleConstraint( request );
    }


    /**
     * ************************************************************************************************************************************
     * BEGIN REVIEWMGR
     * **************************************************************************************************************************************
     */
    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_OBJ_SEARCH + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findPermsByObj( FortRequest request )
    {
        return reviewMgrImpl.findObjPermissions( request );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_ASGNED_CONSTRAINTS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedUsersConstraints( FortRequest request )
    {
        return reviewMgrImpl.assignedUsersConstraints( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_ASGNED_CONSTRAINTS_KEY + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedUsersConstraintsKey( FortRequest request )
    {
        return reviewMgrImpl.assignedUsersConstraintsKey( request );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_ROLES + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse permissionRoles( FortRequest request )
    {
        return reviewMgrImpl.permissionRolesM( request );
    }


    @POST
    @Path("/" + HttpIds.ROLE_FIND_CONSTRAINTS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findRoleConstraints( FortRequest request )
    {
        return reviewMgrImpl.findRoleConstraintsM( request );
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.PERM_USERS_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedPermissionUsers( FortRequest request )
    {
        return reviewMgrImpl.authorizedPermissionUsersM( request );
    }


    @POST
    @Path("/" + HttpIds.PERM_READ_PERM_ATTRIBUTE_SET + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readPermAttributeSet( FortRequest request )
    {
        return reviewMgrImpl.readPermAttributeSetM( request );
    }


    @POST
    @Path("/" + HttpIds.ROLE_PERM_ATTR_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse rolePermissionAttributeSets( FortRequest request )
    {
        return reviewMgrImpl.rolePermissionAttributeSetsM( request );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.RBAC_CREATE_GROUP_SESSION + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse createGroupSession(FortRequest request )
    {
        return accessMgrImpl.createGroupSession( request );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.RBAC_CHECK + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse createSessionCheckAccess( FortRequest request )
    {
        return accessMgrImpl.createSessionCheckAccess( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.RBAC_CHECK_ROLE + "/")
    @RolesAllowed({SUPER_USER, ACCESS_MGR_USER})
    @Override
    public FortResponse isUserInRole( FortRequest request )
    {
        return accessMgrImpl.isUserInRole( request );
    }


    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * BEGIN AUDIT MGR
     * **************************************************************************************************************************************
     */
    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.CFG_READ + "/")
    @RolesAllowed({SUPER_USER, CONFIG_MGR_USER})
    @Override
    public FortResponse readConfig( FortRequest request )
    {
        return configMgrImpl.readConfig( request );
    }

    /**
     * ************************************************************************************************************************************
     * BEGIN GROUPMGR
     * **************************************************************************************************************************************
     */

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_READ + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse readGroup( FortRequest request )
    {
        return groupMgrImpl.readGroup( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addGroup( FortRequest request )
    {
        return groupMgrImpl.addGroup( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_DELETE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse deleteGroup( FortRequest request )
    {
        return groupMgrImpl.deleteGroup( request );
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_UPDATE + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse updateGroup( FortRequest request )
    {
        return groupMgrImpl.updateGroup( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_ROLE_ASGNED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedGroupRoles( FortRequest request )
    {
        return groupMgrImpl.assignedRoles( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_ASGNED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignedGroups( FortRequest request )
    {
        return groupMgrImpl.assignedGroups( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_ASGN + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse assignGroup(FortRequest request)
    {
        return groupMgrImpl.assignGroup( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.GROUP_DEASGN + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse deassignGroup(FortRequest request)
    {
        return groupMgrImpl.deassignGroup( request );
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/{any : .*}")
    @RolesAllowed(
    {
        SUPER_USER,
        ACCESS_MGR_USER,
        ADMIN_MGR_USER,
        REVIEW_MGR_USER,
        DELEGATED_ACCESS_MGR_USER,
        DELEGATED_ADMIN_MGR_USER,
        DELEGATED_REVIEW_MGR_USER,
        PASSWORD_MGR_USER,
        AUDIT_MGR_USER,
        CONFIG_MGR_USER
    } )
    @Override
    public FortResponse invalid(FortRequest request)
    {
        String szError = "Could not find a matching service. HTTP request URI:" + httpRequest.getRequestURI() + ". User: " + httpRequest.getRemoteUser();
        log.warn( szError );
        FortResponse response = new FortResponse();
        response.setErrorCode( GlobalErrIds.REST_NOT_FOUND_ERR );
        response.setErrorMessage( szError );
        return response;
    }
}