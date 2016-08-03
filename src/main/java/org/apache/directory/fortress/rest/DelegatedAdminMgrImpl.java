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

import org.apache.directory.fortress.core.DelAdminMgr;
import org.apache.directory.fortress.core.DelAdminMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.AdminRole;
import org.apache.directory.fortress.core.model.AdminRoleRelationship;
import org.apache.directory.fortress.core.model.OrgUnit;
import org.apache.directory.fortress.core.model.OrgUnitRelationship;
import org.apache.directory.fortress.core.model.UserAdminRole;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.log4j.Logger;


/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class DelegatedAdminMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( DelegatedAdminMgrImpl.class.getName() );

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDADMINMGR
     * **************************************************************************************************************************************
     */

    /* No qualifier */ FortResponse addAdminRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            AdminRole retRole = delegatedAdminMgr.addRole( inRole );
            response.setEntity(retRole);
        }
        catch ( SecurityException se )
        {
            LOG.info( "Caught " + se + " warnId=" + se.getErrorId() );
            response.setErrorCode( se.getErrorId() );
            response.setErrorMessage( se.getMessage() );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deleteAdminRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.deleteRole( inRole );
            response.setEntity(inRole);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateAdminRole( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            AdminRole retRole = delegatedAdminMgr.updateRole( inRole );
            response.setEntity(retRole);
        }
        catch ( SecurityException se )
        {
            LOG.info( "Caught " + se + " errorId=" + se.getErrorId() );
            response.setErrorCode( se.getErrorId() );
            response.setErrorMessage( se.getMessage() );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse assignAdminUser( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAdminRole inRole = (UserAdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.assignUser( inRole );
            response.setEntity(inRole);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deassignAdminUser( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            UserAdminRole inRole = (UserAdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.deassignUser( inRole );
            response.setEntity(inRole);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse addAdminDescendant( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addDescendant( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addAdminAscendant( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addAscendant( relationship.getChild(), relationship.getParent() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse addAdminInheritance( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addInheritance( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deleteAdminInheritance( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.deleteInheritance( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addOrg( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            OrgUnit retOrg = delegatedAdminMgr.add( inOrg );
            response.setEntity(retOrg);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateOrg( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            OrgUnit retOrg = delegatedAdminMgr.update( inOrg );
            response.setEntity(retOrg);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deleteOrg( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            OrgUnit retOrg = delegatedAdminMgr.delete( inOrg );
            response.setEntity(retOrg);
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addOrgDescendant( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addDescendant( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addOrgAscendant( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addAscendant( relationship.getChild(), relationship.getParent() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse addOrgInheritance( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.addInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
            
        return response;
    }

    
    /* No qualifier */ FortResponse deleteOrgInheritance( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance( request.getContextId() );
            delegatedAdminMgr.setAdmin( request.getSession() );
            delegatedAdminMgr.deleteInheritance( relationship.getParent(), relationship.getChild() );
            response.setEntity( relationship );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
}