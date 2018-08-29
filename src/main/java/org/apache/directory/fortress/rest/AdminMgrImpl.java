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

import org.apache.directory.fortress.core.*;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.*;
import org.apache.log4j.Logger;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AdminMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger log = Logger.getLogger( AdminMgrImpl.class.getName() );

    
    /* No qualifier */ FortResponse addUser( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User)request.getEntity();
            User outUser = adminMgr.addUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deleteUser( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User)request.getEntity();
            adminMgr.deleteUser( inUser );
            response.setEntity( inUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse disableUser( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User)request.getEntity();
            adminMgr.disableUser( inUser );
            response.setEntity( inUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateUser( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            User outUser = adminMgr.updateUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse changePassword( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            adminMgr.changePassword( inUser, inUser.getNewPassword() );
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            User outUser = reviewMgr.readUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse lockUserAccount( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            adminMgr.lockUserAccount( inUser );
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            User outUser = reviewMgr.readUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse unlockUserAccount( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            adminMgr.unlockUserAccount( inUser );
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            User outUser = reviewMgr.readUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse resetPassword( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            adminMgr.resetPassword( inUser, inUser.getNewPassword() );
            response.setEntity( inUser );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addRole( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            Role outRole = adminMgr.addRole( inRole );
            response.setEntity( outRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }
    
    
    /* No qualifier */ FortResponse deleteRole( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            adminMgr.deleteRole( inRole );
            response.setEntity( inRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateRole( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            Role outRole = adminMgr.updateRole( inRole );
            response.setEntity( outRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }


    /* No qualifier */ FortResponse assignUser( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            UserRole inRole = (UserRole) request.getEntity();
            adminMgr.assignUser( inRole );
            response.setEntity( inRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse deassignUser( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            UserRole inRole = (UserRole) request.getEntity();
            adminMgr.deassignUser( inRole );
            response.setEntity( inRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse addPermission( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            Permission outPerm = adminMgr.addPermission( inPerm );
            response.setEntity( outPerm );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updatePermission( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            Permission outPerm = adminMgr.updatePermission( inPerm );
            response.setEntity( outPerm );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deletePermission( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            adminMgr.deletePermission( inPerm );
            response.setEntity( inPerm );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addPermObj( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermObj inObj = (PermObj) request.getEntity();
            PermObj outObj = adminMgr.addPermObj( inObj );
            response.setEntity( outObj );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updatePermObj( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermObj inObj = (PermObj) request.getEntity();
            PermObj outObj = adminMgr.updatePermObj( inObj );
            response.setEntity( outObj );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deletePermObj( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermObj inObj = (PermObj) request.getEntity();
            adminMgr.deletePermObj( inObj );
            response.setEntity( inObj );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    private void grantPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
        adminMgr.setAdmin( request.getSession() );
        Role role = new Role( permGrant.getRoleNm() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( false );
        adminMgr.grantPermission( perm, role );
    }

    
    private void grantAdminPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
        delegatedAdminMgr.setAdmin( request.getSession() );
        AdminRole role = new AdminRole( permGrant.getRoleNm() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( true );
        delegatedAdminMgr.grantPermission( perm, role );
    }

    
    private void revokePerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
        adminMgr.setAdmin( request.getSession() );
        Role role = new Role( permGrant.getRoleNm() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( false );
        adminMgr.revokePermission( perm, role );
    }

    
    private void revokeAdminPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
        delegatedAdminMgr.setAdmin( request.getSession() );
        AdminRole role = new AdminRole( permGrant.getRoleNm() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( true );
        delegatedAdminMgr.revokePermission( perm, role );
    }

    
    private void grantUserPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
        adminMgr.setAdmin( request.getSession() );
        User user = new User( permGrant.getUserId() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( false );
        adminMgr.grantPermission( perm, user );
    }

    
    private void grantAdminUserPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
        delegatedAdminMgr.setAdmin( request.getSession() );
        User user = new User( permGrant.getUserId() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( true );
        delegatedAdminMgr.grantPermission( perm, user );
    }

    
    private void revokeUserPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
        adminMgr.setAdmin( request.getSession() );
        User user = new User( permGrant.getUserId() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( false );
        adminMgr.revokePermission( perm, user );
    }

    
    private void revokeAdminUserPerm( FortRequest request ) throws SecurityException
    {
        PermGrant permGrant = (PermGrant) request.getEntity();
        DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
        delegatedAdminMgr.setAdmin( request.getSession() );
        User user = new User( permGrant.getUserId() );
        Permission perm = new Permission( permGrant.getObjName(), permGrant.getOpName(), permGrant.getObjId() );
        perm.setAdmin( true );
        delegatedAdminMgr.revokePermission( perm, user );
    }

    
    /* No qualifier */ FortResponse grant(FortRequest request, FortressServiceImpl fortressService)
    {
        FortResponse response = createResponse();

        try
        {
            PermGrant permGrant = (PermGrant) request.getEntity();
        
            if ( permGrant.isAdmin() )
            {
                grantAdminPerm( request );
            }
            else
            {
                grantPerm( request );
            }
            
            response.setEntity(permGrant);
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse revoke(FortRequest request, FortressServiceImpl fortressService)
    {
        FortResponse response = createResponse();

        try
        {
            PermGrant permGrant = (PermGrant) request.getEntity();
            
            if (permGrant.isAdmin())
            {
                revokeAdminPerm( request );
            }
            else
            {
                revokePerm( request );
            }
            response.setEntity( permGrant );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse grantUser(FortRequest request, FortressServiceImpl fortressService)
    {
        FortResponse response = createResponse();

        try
        {
            PermGrant permGrant = (PermGrant) request.getEntity();
            
            if ( permGrant.isAdmin() )
            {
                grantAdminUserPerm( request );
            }
            else
            {
                grantUserPerm( request );
            }
            
            response.setEntity( permGrant );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse revokeUser(FortRequest request, FortressServiceImpl fortressService)
    {
        FortResponse response = createResponse();

        try
        {
            PermGrant permGrant = (PermGrant) request.getEntity();
            
            if ( permGrant.isAdmin() )
            {
                revokeAdminUserPerm( request );
            }
            else
            {
                revokeUserPerm( request );
            }
            
            response.setEntity( permGrant );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addDescendant( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            RoleRelationship relationship = (RoleRelationship) request.getEntity();
            adminMgr.addDescendant(relationship.getParent(), relationship.getChild());
            response.setEntity( relationship );

        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addAscendant( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            RoleRelationship relationship = (RoleRelationship) request.getEntity();
            adminMgr.addAscendant(relationship.getChild(), relationship.getParent());
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse addInheritance( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            RoleRelationship relationship = (RoleRelationship) request.getEntity();
            adminMgr.addInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteInheritance( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            RoleRelationship relationship = (RoleRelationship) request.getEntity();
            adminMgr.deleteInheritance( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse createSsdSet( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.createSsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse updateSsdSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.updateSsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addSsdRoleMember( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            Role role = new Role( request.getValue() );
            SDSet outSet = adminMgr.addSsdRoleMember( inSet, role );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteSsdRoleMember( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            Role role = new Role( request.getValue() );
            SDSet outSet = adminMgr.deleteSsdRoleMember( inSet, role );
            response.setEntity(outSet);
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteSsdSet( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.deleteSsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse setSsdSetCardinality( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.setSsdSetCardinality( inSet, inSet.getCardinality() );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse createDsdSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.createDsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateDsdSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.updateDsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse addDsdRoleMember( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            Role role = new Role(request.getValue());
            SDSet outSet = adminMgr.addDsdRoleMember( inSet, role );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteDsdRoleMember( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            Role role = new Role(request.getValue());
            SDSet outSet = adminMgr.deleteDsdRoleMember( inSet, role );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteDsdSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.deleteDsdSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse setDsdSetCardinality( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = adminMgr.setDsdSetCardinality( inSet, inSet.getCardinality() );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }


    /* No qualifier */ FortResponse addRoleConstraint( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            UserRole inRole = (UserRole) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            RoleConstraint outRole = adminMgr.addRoleConstraint( inRole, inConstraint );
            response.setEntity( outRole );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse removeRoleConstraint( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            UserRole inRole = (UserRole) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            adminMgr.removeRoleConstraint( inRole, inConstraint );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse removeRoleConstraintWid( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            UserRole inRole = (UserRole) request.getEntity();
            String szConstraintId = request.getValue();
            adminMgr.removeRoleConstraint( inRole, szConstraintId );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse enableRoleConstraint( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            adminMgr.enableRoleConstraint( inRole, inConstraint );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        return response;
    }


    /* No qualifier */ FortResponse disableRoleConstraint( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            adminMgr.disableRoleConstraint( inRole, inConstraint );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        return response;
    }


    /* No qualifier */ FortResponse addPermissionAttributeToSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermissionAttribute inAttr = (PermissionAttribute) request.getEntity();
            String attrName = request.getValue();
            PermissionAttribute outAttr = adminMgr.addPermissionAttributeToSet( inAttr, attrName );
            response.setEntity( outAttr );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse updatePermissionAttributeInSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermissionAttribute inAttr = (PermissionAttribute) request.getEntity();
            String attrName = request.getValue();
            boolean isReplace = request.getIsFlag();
            adminMgr.updatePermissionAttributeInSet( inAttr, attrName, isReplace );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse removePermissionAttributeFromSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermissionAttribute inAttr = (PermissionAttribute) request.getEntity();
            String attrName = request.getValue();
            adminMgr.removePermissionAttributeFromSet( inAttr, attrName );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    /* No qualifier */ FortResponse addPermissionAttributeSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermissionAttributeSet inSet = (PermissionAttributeSet) request.getEntity();
            PermissionAttributeSet outSet = adminMgr.addPermissionAttributeSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse deletePermissionAttributeSet( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AdminMgr adminMgr = AdminMgrFactory.createInstance( request.getContextId() );
            adminMgr.setAdmin( request.getSession() );
            PermissionAttributeSet inSet = (PermissionAttributeSet) request.getEntity();
            adminMgr.deletePermissionAttributeSet( inSet );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }
}