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

import org.apache.directory.fortress.core.DelReviewMgr;
import org.apache.directory.fortress.core.DelReviewMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.AdminRole;
import org.apache.directory.fortress.core.model.OrgUnit;
import org.apache.directory.fortress.core.model.UserAdminRole;
import org.apache.directory.fortress.core.model.User;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class DelegatedReviewMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( DelegatedReviewMgrImpl.class.getName() );

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDREVIEWMGR
     * **************************************************************************************************************************************
     */

    /* No qualifier */ FortResponse readAdminRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            AdminRole outRole = delegatedReviewMgr.readRole( inRole );
            response.setEntity( outRole );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse findAdminRoles( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            String searchVal = request.getValue();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            delegatedReviewMgr.setAdmin( request.getSession() );
            List<AdminRole> outRoles = delegatedReviewMgr.findRoles( searchVal );
            response.setEntities( outRoles );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse assignedAdminRoles( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            User inUser = (User)request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            delegatedReviewMgr.setAdmin( request.getSession() );
            List<UserAdminRole> uRoles = delegatedReviewMgr.assignedRoles( inUser );
            response.setEntities( uRoles );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse assignedAdminUsers( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            delegatedReviewMgr.setAdmin( request.getSession() );
            List<User> users = delegatedReviewMgr.assignedUsers( inRole );
            response.setEntities( users );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse readOrg( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            delegatedReviewMgr.setAdmin( request.getSession() );
            OrgUnit returnOrg = delegatedReviewMgr.read( inOrg );
            response.setEntity( returnOrg );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse searchOrg( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance( request.getContextId() );
            delegatedReviewMgr.setAdmin( request.getSession() );
            List<OrgUnit> orgs = delegatedReviewMgr.search( inOrg.getType(), inOrg.getName() );
            response.setEntities( orgs );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
}