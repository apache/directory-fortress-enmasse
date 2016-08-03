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

import org.apache.directory.fortress.core.AuditMgr;
import org.apache.directory.fortress.core.AuditMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.AuthZ;
import org.apache.directory.fortress.core.model.Bind;
import org.apache.directory.fortress.core.model.Mod;
import org.apache.directory.fortress.core.model.UserAudit;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AuditMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger log = Logger.getLogger( AuditMgrImpl.class.getName() );

    /**
     * ************************************************************************************************************************************
     * BEGIN AUDIT
     * **************************************************************************************************************************************
     */

    /* No qualifier */ FortResponse searchBinds(FortRequest request)
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAudit inAudit = (UserAudit) request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<Bind> outAudit = auditMgr.searchBinds( inAudit );
            response.setEntities( outAudit );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse getUserAuthZs(FortRequest request)
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<AuthZ> outAudit = auditMgr.getUserAuthZs( inAudit );
            response.setEntities( outAudit );
        }
        catch (SecurityException se)
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse searchAuthZs(FortRequest request)
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<AuthZ> outAudit = auditMgr.searchAuthZs( inAudit );
            response.setEntities( outAudit );
        }
        catch (SecurityException se)
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse searchUserSessions(FortRequest request)
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<Mod> outAudit = auditMgr.searchUserSessions( inAudit );
            response.setEntities( outAudit );
        }
        catch (SecurityException se)
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse searchAdminMods(FortRequest request)
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<Mod> outAudit = auditMgr.searchAdminMods( inAudit );
            response.setEntities( outAudit );
        }
        catch (SecurityException se)
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse searchInvalidUsers(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance( request.getContextId() );
            auditMgr.setAdmin( request.getSession() );
            List<AuthZ> outAudit = auditMgr.searchInvalidUsers( inAudit );
            response.setEntities( outAudit );
        }
        catch (SecurityException se)
        {
            createError( response, log, se );
        }
        
        return response;
    }
}