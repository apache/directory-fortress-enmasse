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

import org.apache.directory.fortress.core.DelAccessMgr;
import org.apache.directory.fortress.core.DelAccessMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.RolePerm;
import org.apache.directory.fortress.core.model.UserAdminRole;
import org.apache.directory.fortress.core.model.Permission;
import org.apache.directory.fortress.core.model.Role;
import org.apache.directory.fortress.core.model.Session;
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
class DelegatedAccessMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( DelegatedAccessMgrImpl.class.getName() );

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDACCESSMGR
     * **************************************************************************************************************************************
     */

    /* No qualifier */ FortResponse canAssign(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            UserRole uRole = (UserRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            boolean result = accessMgr.canAssign( session, new User( uRole.getUserId() ), new Role( uRole.getName() ) );
            response.setSession( session );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse canDeassign(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            UserRole uRole = (UserRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            boolean result = accessMgr.canDeassign( session, new User( uRole.getUserId() ), new Role( uRole.getName() ) );
            response.setSession( session );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse canGrant(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            RolePerm context = (RolePerm) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            boolean result = accessMgr.canGrant( session, new Role( context.getRole().getName() ), context.getPerm() );
            response.setSession( session );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse canRevoke(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            RolePerm context = (RolePerm) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            boolean result = accessMgr.canRevoke( session, new Role( context.getRole().getName() ), context.getPerm() );
            response.setSession( session );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    public FortResponse checkAdminAccess(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            Permission perm = (Permission) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            perm.setAdmin( true );
            boolean result = accessMgr.checkAccess( session, perm );
            response.setSession( session );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addActiveAdminRole(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            UserAdminRole uAdminRole = (UserAdminRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            accessMgr.addActiveRole( session, uAdminRole );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse dropActiveAdminRole(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            UserAdminRole uAdminRole = (UserAdminRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            accessMgr.dropActiveRole( session, uAdminRole );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse sessionAdminRoles(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            List<UserAdminRole> roles = accessMgr.sessionAdminRoles( session );
            response.setEntities( roles );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse sessionAdminPermissions(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            List<Permission> perms = accessMgr.sessionPermissions( session );
            response.setSession( session );
            response.setEntities( perms );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse authorizedSessionRoles(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            Set<String> roles = accessMgr.authorizedAdminRoles( session );
            response.setValueSet( roles );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
}