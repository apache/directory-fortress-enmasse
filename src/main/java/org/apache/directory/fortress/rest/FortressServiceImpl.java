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

import jakarta.annotation.security.RolesAllowed;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;

import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.model.*;
import org.apache.directory.fortress.core.rest.HttpIds;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Service;


/**
 * Implementation for Fortress Rest Service methods forwards to delegate.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Service("fortressService")
public class FortressServiceImpl implements FortressService
{
    private static final Logger LOG = LoggerFactory.getLogger( FortressServiceImpl.class.getName() );
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
     * default contructor
     */
    public FortressServiceImpl()
    {
    }

    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_ADD + "/")
    @RolesAllowed({SUPER_USER, ADMIN_MGR_USER})
    @Override
    public FortResponse addUser( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.disableUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updateUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.changePassword( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.lockUserAccount( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.unlockUserAccount( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.resetPassword( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updateRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.assignUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deassignUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addPermission( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updatePermission( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deletePermission( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addPermObj( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updatePermObj( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deletePermObj( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.grant( request, this );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.revoke( request, this );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.grantUser( request, this );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.revokeUser( request, this );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addDescendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addAscendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.createSsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updateSsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addSsdRoleMember( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteSsdRoleMember( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteSsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.setSsdSetCardinality( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.createDsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updateDsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addDsdRoleMember( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteDsdRoleMember( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deleteDsdSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.setDsdSetCardinality( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addRoleConstraint( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.removeRoleConstraint( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.removeRoleConstraintWid( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addPermissionAttributeSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.deletePermissionAttributeSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.addPermissionAttributeToSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.removePermissionAttributeFromSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.updatePermissionAttributeInSet( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.enableRoleConstraint( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = adminMgrImpl.disableRoleConstraint( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.readPermission( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.readPermObj( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findPermissions( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findObjPermissions( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findAnyPermissions( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findPermObjs( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.readRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findRoles( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.readUserM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findUsersM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.assignedUsersM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.assignedUsersConstraints( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.assignedUsersConstraintsKey( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.assignedRolesM( request );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.USER_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedUsers( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.authorizedUsersM( request );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @POST
    @Path("/" + HttpIds.ROLE_AUTHZED + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse authorizedRoles( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.authorizedRoleM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.permissionRolesM( request );
        return response;
    }


    @POST
    @Path("/" + HttpIds.ROLE_FIND_CONSTRAINTS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse findRoleConstraints( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.findRoleConstraintsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.rolePermissionsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.userPermissionsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.authorizedPermissionRolesM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.permissionUsersM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.authorizedPermissionUsersM( request );
        return response;
    }


    @POST
    @Path("/" + HttpIds.PERM_READ_PERM_ATTRIBUTE_SET + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse readPermAttributeSet( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.readPermAttributeSetM( request );
        return response;
    }


    @POST
    @Path("/" + HttpIds.ROLE_PERM_ATTR_SETS + "/")
    @RolesAllowed({SUPER_USER, REVIEW_MGR_USER})
    @Override
    public FortResponse rolePermissionAttributeSets( FortRequest request )
    {
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.rolePermissionAttributeSetsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.ssdRoleSetsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.ssdRoleSetM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.ssdRoleSetRolesM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.ssdRoleSetCardinalityM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.ssdSetsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.dsdRoleSetsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.dsdRoleSetM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.dsdRoleSetRolesM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.dsdRoleSetCardinalityM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = reviewMgrImpl.dsdSetsM( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addAdminRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.deleteAdminRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.updateAdminRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.assignAdminUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.deassignAdminUser( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addAdminDescendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addAdminAscendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addAdminInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.deleteAdminInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addOrg( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.updateOrg( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.deleteOrg( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addOrgDescendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addOrgAscendant( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.addOrgInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedAdminMgrImpl.deleteOrgInheritance( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.readAdminRole( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.findAdminRoles( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.assignedAdminRoles( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.assignedAdminUsers( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.readOrg( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = delegatedReviewMgrImpl.searchOrg( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.addPolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.updatePolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.deletePolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.readPolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.searchPolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.updateUserPolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = pswdPolicyMgrImpl.deleteUserPolicy( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.searchBinds( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.getUserAuthZs( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.searchAuthZs( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.searchUserSessions( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.searchAdminMods( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = auditMgrImpl.searchInvalidUsers( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = configMgrImpl.addConfig( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = configMgrImpl.updateConfig( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = configMgrImpl.deleteConfig( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = configMgrImpl.readConfig( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.readGroup( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.addGroup( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.deleteGroup( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.updateGroup( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.assignedRoles( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.assignedGroups( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.assignGroup( request );
        return response;
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
        FortResponse response = SecUtils.initializeSession(request, httpRequest);
        if( response == null )
            response = groupMgrImpl.deassignGroup( request );
        return response;
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
        LOG.warn( szError );
        FortResponse response = new FortResponse();
        response.setErrorCode( GlobalErrIds.REST_NOT_FOUND_ERR );
        response.setErrorMessage( szError );
        return response;
    }
}
