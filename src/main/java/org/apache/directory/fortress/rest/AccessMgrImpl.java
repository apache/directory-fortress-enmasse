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

import org.apache.directory.fortress.core.AccessMgr;
import org.apache.directory.fortress.core.AccessMgrFactory;
import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.ant.RoleConstraintAnt;
import org.apache.directory.fortress.core.model.*;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AccessMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( AccessMgrImpl.class.getName() );
    
    /** A flag for trusted sessions */
    private static final boolean TRUSTED = true;
    
    /** A flag for untrusted sessions */
    private static final boolean UNTRUSTED = false;

    /**
     * ************************************************************************************************************************************
     * BEGIN ACCESSMGR
     * **************************************************************************************************************************************
     */
    /* No qualifier */ FortResponse authenticate( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            User inUser = (User) request.getEntity();
            Session outSession = accessMgr.authenticate( inUser.getUserId(), inUser.getPassword() );
            response.setSession( outSession );
            response.setErrorCode( GlobalErrIds.NO_ERROR );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /**
     * Creates an untrusted session
     * 
     * @param request The request We want to create a session for
     * @return The created response
     */
    /* no qualifier*/ FortResponse createSession( FortRequest request )
    {
        return createSession( request, UNTRUSTED );
    }

    
    /**
     * Creates a trusted session
     * 
     * @param request The request We want to create a session for
     * @return The created response
     */
    /* no qualifier*/ FortResponse createSessionTrusted( FortRequest request )
    {
        return createSession( request, TRUSTED );
    }

    /**
     * Creates a group-type trusted session
     *
     * @param request The request We want to create a session for
     * @return The created response
     */
    /* no qualifier*/ FortResponse createGroupSession( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Group inGroup = (Group) request.getEntity();
            Session outSession = accessMgr.createSession( inGroup );
            response.setSession( outSession );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }

    
    /**
     * Creates a session, trusted or untrested
     * 
     * @param request The request We want to create a session for
     * @param trusted Is the session trusted or not
     * @return The created response
     */
    private FortResponse createSession( FortRequest request, boolean trusted )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            User inUser = (User) request.getEntity();
            Session outSession = accessMgr.createSession( inUser, trusted );
            response.setSession( outSession );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
    
    
    /**
     * Perform user RBAC authorization.
     *
     * @param request The {@link FortRequest} we have to check
     * @return a {@link FortResponse} containing the response
     */
    /* no qualifier*/ FortResponse checkAccess( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Permission perm = (Permission)request.getEntity();
            perm.setAdmin( false );
            Session session = request.getSession();
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

    
    /**
     * Perform user RBAC authorization.
     *
     * @param request The {@link FortRequest} we have to check
     * @return a {@link FortResponse} containing the response
     */
    /* no qualifier*/ FortResponse createSessionCheckAccess( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Permission perm = (Permission)request.getEntity();
            perm.setAdmin( false );
            User user = (User) request.getEntity2();
            boolean isTrusted = request.getIsFlag();
            boolean result = accessMgr.checkAccess( user, perm, isTrusted );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /**
     * Perform user ROLE check.
     *
     * @param request The {@link FortRequest} we have to check
     * @return a {@link FortResponse} containing the response
     */
    /* no qualifier*/ FortResponse isUserInRole( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Role role = (Role)request.getEntity();
            User user = (User) request.getEntity2();
            boolean isTrusted = request.getIsFlag();
            boolean result = accessMgr.isUserInRole( user, role, isTrusted );
            response.setAuthorized( result );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }


    /* No qualifier */ FortResponse sessionPermissions( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
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

    
    /* No qualifier */ FortResponse sessionRoles( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            List<UserRole> roles = accessMgr.sessionRoles( session );
            response.setEntities( roles );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse authorizedSessionRoles( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            Set<String> roles = accessMgr.authorizedRoles( session );
            response.setValueSet( roles );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
    

    /* No qualifier */ FortResponse addActiveRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            UserRole uRole = (UserRole)request.getEntity();
            Session session = request.getSession();
            accessMgr.addActiveRole( session, uRole );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse dropActiveRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            UserRole uRole = (UserRole)request.getEntity();
            Session session = request.getSession();
            accessMgr.dropActiveRole( session, uRole );
            response.setSession( session );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
    

    /* No qualifier */ FortResponse getUserId( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            String userId = accessMgr.getUserId( session );
            User outUser = new User( userId );
            response.setSession( session );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse getUser( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance( request.getContextId() );
            Session session = request.getSession();
            User outUser = accessMgr.getUser( session );
            response.setSession( session );
            response.setEntity( outUser );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
}