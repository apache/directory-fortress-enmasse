/*
 * This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2014 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
package org.openldap.enmasse;

import org.openldap.fortress.PwPolicyMgr;
import org.openldap.fortress.PwPolicyMgrFactory;
import org.openldap.fortress.SecurityException;
import org.openldap.fortress.rbac.PwPolicy;
import org.openldap.fortress.rest.FortRequest;
import org.openldap.fortress.rest.FortResponse;
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
        catch (org.openldap.fortress.SecurityException se)
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