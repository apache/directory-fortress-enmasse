/*
 * Copyright (c) 2011-2012. Joshua Tree Software, LLC.  All Rights Reserved.
 */
package com.jts.enmasse;

import com.jts.fortress.DelReviewMgr;
import com.jts.fortress.DelReviewMgrFactory;
import com.jts.fortress.SecurityException;
import com.jts.fortress.rbac.AdminRole;
import com.jts.fortress.rbac.OrgUnit;
import com.jts.fortress.rbac.UserAdminRole;
import com.jts.fortress.rbac.User;
import com.jts.fortress.rest.FortRequest;
import com.jts.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 * @created February 19, 2012
 */
class DelegatedReviewMgrImpl
{
    private static final String CLS_NM = DelegatedReviewMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDREVIEWMGR
     * **************************************************************************************************************************************
     */

    FortResponse readAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            AdminRole outRole = delegatedReviewMgr.readRole(inRole);
            response.setEntity(outRole);
            response.setErrorCode(0);
        }
        catch (com.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse findAdminRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            String searchVal = request.getValue();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            delegatedReviewMgr.setAdmin(request.getSession());
            List<AdminRole> outRoles = delegatedReviewMgr.findRoles(searchVal);
            response.setEntities(outRoles);
            response.setErrorCode(0);

        }
        catch (SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse assignedAdminRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            User inUser = (User)request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            delegatedReviewMgr.setAdmin(request.getSession());
            List<UserAdminRole> uRoles = delegatedReviewMgr.assignedRoles(inUser);
            response.setEntities(uRoles);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse assignedAdminUsers(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            delegatedReviewMgr.setAdmin(request.getSession());
            List<User> users = delegatedReviewMgr.assignedUsers(inRole);
            response.setEntities(users);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse readOrg(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            delegatedReviewMgr.setAdmin(request.getSession());
            OrgUnit returnOrg = delegatedReviewMgr.read(inOrg);
            response.setEntity(returnOrg);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse searchOrg(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelReviewMgr delegatedReviewMgr = DelReviewMgrFactory.createInstance(request.getContextId());
            delegatedReviewMgr.setAdmin(request.getSession());
            List<OrgUnit> orgs = delegatedReviewMgr.search(inOrg.getType(), inOrg.getName());
            response.setEntities(orgs);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}