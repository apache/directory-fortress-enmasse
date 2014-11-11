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
import org.apache.directory.fortress.core.rbac.PwPolicy;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 */
class PswdPolicyMgrImpl
{
    private static final String CLS_NM = PswdPolicyMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN PSWDPOLICYMGR
     * **************************************************************************************************************************************
     */
    FortResponse addPolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            policyMgr.add(inPolicy);
            response.setEntity(inPolicy);
            response.setErrorCode(0);
        }
        catch (org.apache.directory.fortress.core.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse updatePolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            policyMgr.update(inPolicy);
            response.setEntity(inPolicy);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse deletePolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            policyMgr.delete(inPolicy);
            response.setEntity(inPolicy);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse readPolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        PwPolicy outPolicy;
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            outPolicy = policyMgr.read(inPolicy.getName());
            response.setEntity(outPolicy);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse searchPolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        List<PwPolicy> policyList;
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            policyList = policyMgr.search(inPolicy.getName());
            response.setEntities(policyList);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse updateUserPolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            PwPolicy inPolicy = (PwPolicy) request.getEntity();
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            String userId = request.getValue();
            policyMgr.updateUserPolicy(userId, inPolicy.getName());
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse deleteUserPolicy(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            PwPolicyMgr policyMgr = PwPolicyMgrFactory.createInstance(request.getContextId());
            policyMgr.setAdmin(request.getSession());
            String userId = request.getValue();
            policyMgr.deletePasswordPolicy(userId);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}