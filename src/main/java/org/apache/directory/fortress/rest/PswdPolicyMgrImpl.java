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

import org.apache.directory.fortress.core.PwPolicyMgr;
import org.apache.directory.fortress.core.PwPolicyMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.PwPolicy;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class PswdPolicyMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger( PswdPolicyMgrImpl.class.getName() );

    /**
     * ************************************************************************************************************************************
     * BEGIN PSWDPOLICYMGR
     * **************************************************************************************************************************************
     */
    /* No qualifier */ FortResponse addPolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            policyMgr.add( inPolicy );
            response.setEntity( inPolicy );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updatePolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            policyMgr.update( inPolicy );
            response.setEntity( inPolicy );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deletePolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            policyMgr.delete( inPolicy );
            response.setEntity( inPolicy );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse readPolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        PwPolicy outPolicy;
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            outPolicy = policyMgr.read( inPolicy.getName() );
            response.setEntity( outPolicy );
        }
        catch ( SecurityException se )
        {
            response.setErrorCode( se.getErrorId() );
            response.setErrorMessage( se.getMessage() );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse searchPolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        List<PwPolicy> policyList;
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            policyList = policyMgr.search( inPolicy.getName() );
            response.setEntities( policyList );
        }
        catch ( SecurityException se )
        {
            response.setErrorCode( se.getErrorId() );
            response.setErrorMessage( se.getMessage() );
        }
        
        return response;
    }
    
    
    /* No qualifier */ FortResponse updateUserPolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            String userId = request.getValue();
            policyMgr.updateUserPolicy( userId, inPolicy.getName() );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse deleteUserPolicy( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance( request.getContextId() );
            policyMgr.setAdmin( request.getSession() );
            String userId = request.getValue();
            policyMgr.deletePasswordPolicy( userId );
        }
        catch ( SecurityException se )
        {
            createError( response, LOG, se );
        }
        
        return response;
    }
}