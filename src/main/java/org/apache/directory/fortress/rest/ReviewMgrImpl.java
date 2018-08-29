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

import org.apache.commons.lang.StringUtils;
import org.apache.directory.fortress.core.ReviewMgr;
import org.apache.directory.fortress.core.ReviewMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.OrgUnit;
import org.apache.directory.fortress.core.model.PermObj;
import org.apache.directory.fortress.core.model.Permission;
import org.apache.directory.fortress.core.model.PermissionAttributeSet;
import org.apache.directory.fortress.core.model.Role;
import org.apache.directory.fortress.core.model.RoleConstraint;
import org.apache.directory.fortress.core.model.SDSet;
import org.apache.directory.fortress.core.model.User;
import org.apache.directory.fortress.core.model.UserRole;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.Set;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class ReviewMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( ReviewMgrImpl.class.getName() );

    /* No qualifier */  FortResponse readPermission( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            Permission inPerm = (Permission) request.getEntity();
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Permission retPerm = reviewMgr.readPermission( inPerm );
            response.setEntity( retPerm );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse readPermObj( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PermObj inObj = (PermObj) request.getEntity();
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            PermObj retObj = reviewMgr.readPermObj( inObj );
            response.setEntity( retObj );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse findPermissions( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            List<Permission> perms = reviewMgr.findPermissions( inPerm );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }


    /* No qualifier */  FortResponse findObjPermissions( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            PermObj inObj = (PermObj) request.getEntity();
            List<Permission> perms = reviewMgr.findPermsByObj( inObj );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse findAnyPermissions( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            List<Permission> perms = reviewMgr.findAnyPermissions( inPerm );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse findPermObjs( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            PermObj inObj = (PermObj) request.getEntity();
            List<PermObj> objs = null;
            
            if ( StringUtils.isNotEmpty( inObj.getOu() ) )
            {
                objs = reviewMgr.findPermObjs( new OrgUnit( inObj.getOu(), OrgUnit.Type.PERM ) );
            }
            else
            {
                objs = reviewMgr.findPermObjs( inObj );
            }
            
            response.setEntities(objs);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse readRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            Role outRole = reviewMgr.readRole( inRole );
            response.setEntity( outRole );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse findRoles( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            String searchValue = request.getValue();
            
            if ( request.getLimit() != null )
            {
                List<String> retRoles = reviewMgr.findRoles( searchValue, request.getLimit() );
                response.setValues( retRoles );
            }
            else
            {
                List<Role> roles = reviewMgr.findRoles( searchValue );
                response.setEntities( roles );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse readUserM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            User outUser = reviewMgr.readUser( inUser );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse findUsersM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            
            if ( request.getLimit() != null )
            {
                List<String> retUsers = reviewMgr.findUsers( inUser, request.getLimit() );
                response.setValues( retUsers );
            }
            else
            {
                List<User> retUsers;
                
                if ( StringUtils.isNotEmpty( inUser.getOu() ) )
                {
                    retUsers = reviewMgr.findUsers( new OrgUnit( inUser.getOu(), OrgUnit.Type.USER ) );
                }
                else
                {
                    retUsers = reviewMgr.findUsers( inUser );
                }
                
                response.setEntities( retUsers );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse assignedUsersM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            
            if ( request.getLimit() != null )
            {
                List<String> retUsers = reviewMgr.assignedUsers( inRole, request.getLimit() );
                response.setValues( retUsers );
            }
            else
            {
                List<User> users = reviewMgr.assignedUsers( inRole );
                response.setEntities( users );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse assignedUsersConstraints( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            List<User> users = reviewMgr.assignedUsers( inRole, inConstraint );
            response.setEntities( users );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse assignedUsersConstraintsKey( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            RoleConstraint inConstraint = (RoleConstraint) request.getEntity2();
            List<UserRole> uRoles = reviewMgr.assignedUsers( inRole, inConstraint.getType(), inConstraint.getKey() );
            response.setEntities( uRoles );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse assignedRolesM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            
            if ( StringUtils.isNotEmpty( request.getValue() ) )
            {
                String userId = request.getValue();
                List<String> retRoles = reviewMgr.assignedRoles( userId );
                response.setValues( retRoles );
            }
            else
            {
                User inUser = (User) request.getEntity();
                List<UserRole> uRoles = reviewMgr.assignedRoles( inUser );
                response.setEntities( uRoles );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse authorizedUsersM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            List<User> users = reviewMgr.authorizedUsers( inRole );
            response.setEntities( users );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse authorizedRoleM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            Set<String> outSet = reviewMgr.authorizedRoles( inUser );
            response.setValueSet( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse permissionRolesM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            List<String> outList = reviewMgr.permissionRoles( inPerm );
            response.setValues( outList );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse authorizedPermissionRolesM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Permission inPerm = (Permission) request.getEntity();
            Set<String> outSet = reviewMgr.authorizedPermissionRoles( inPerm );
            response.setValueSet( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse permissionUsersM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            Permission inPerm = (Permission) request.getEntity();
            List<String> outList = reviewMgr.permissionUsers( inPerm );
            response.setValues( outList );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse authorizedPermissionUsersM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            Permission inPerm = (Permission) request.getEntity();
            Set<String> outSet = reviewMgr.authorizedPermissionUsers( inPerm );
            response.setValueSet( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse userPermissionsM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            List<Permission> perms = reviewMgr.userPermissions( inUser );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse rolePermissionsM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            boolean noInheritance = request.getIsFlag();
            List<Permission> perms = reviewMgr.rolePermissions( inRole, noInheritance );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse ssdRoleSetsM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            List<SDSet> outSets = reviewMgr.ssdRoleSets( inRole );
            response.setEntities( outSets );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse ssdRoleSetM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = reviewMgr.ssdRoleSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse ssdRoleSetRolesM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            SDSet inSet = (SDSet) request.getEntity();
            Set<String> outSet = reviewMgr.ssdRoleSetRoles( inSet );
            response.setValueSet( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse ssdRoleSetCardinalityM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            SDSet inSet = (SDSet) request.getEntity();
            int cardinality = reviewMgr.ssdRoleSetCardinality( inSet );
            inSet.setCardinality( cardinality );
            response.setEntity( inSet );
        }
        catch ( SecurityException se )
        {
            LOG.info( "Caught " + se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse ssdSetsM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            SDSet inSdSet = (SDSet) request.getEntity();
            List<SDSet> outSets = reviewMgr.ssdSets( inSdSet );
            response.setEntities( outSets );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse dsdRoleSetsM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            List<SDSet> outSets = reviewMgr.dsdRoleSets( inRole );
            response.setEntities( outSets );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse dsdRoleSetM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            SDSet inSet = (SDSet) request.getEntity();
            SDSet outSet = reviewMgr.dsdRoleSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse dsdRoleSetRolesM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            SDSet inSet = (SDSet) request.getEntity();
            Set<String> outSet = reviewMgr.dsdRoleSetRoles( inSet );
            response.setValueSet( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse dsdRoleSetCardinalityM( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            SDSet inSet = (SDSet) request.getEntity();
            int cardinality = reviewMgr.dsdRoleSetCardinality( inSet );
            inSet.setCardinality( cardinality );
            response.setEntity( inSet );
        }
        catch ( SecurityException se )
        {
            LOG.info( "Caught " + se );
        }
        
        return response;
    }

    
    /* No qualifier */  FortResponse dsdSetsM( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            SDSet inSdSet = (SDSet) request.getEntity();
            List<SDSet> outSets = reviewMgr.dsdSets( inSdSet );
            response.setEntities( outSets );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }


    /* No qualifier */  FortResponse findRoleConstraintsM(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            User inUser = (User) request.getEntity();
            Permission inPerm = (Permission) request.getEntity2();
            RoleConstraint.RCType inType = RoleConstraint.RCType.valueOf( request.getValue() );
            List<RoleConstraint> outConstraints = reviewMgr.findRoleConstraints( inUser, inPerm, inType );
            response.setEntities( outConstraints );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse rolePermissionAttributeSetsM(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();
            boolean isReplace = request.getIsFlag();
            List<PermissionAttributeSet> retAttrSets = reviewMgr.rolePermissionAttributeSets( inRole, isReplace );
            response.setEntities( retAttrSets );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse readPermAttributeSetM(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ReviewMgr reviewMgr = ReviewMgrFactory.createInstance( request.getContextId() );
            reviewMgr.setAdmin( request.getSession() );
            PermissionAttributeSet inSet = (PermissionAttributeSet) request.getEntity();
            PermissionAttributeSet outSet = reviewMgr.readPermAttributeSet( inSet );
            response.setEntity( outSet );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }

}