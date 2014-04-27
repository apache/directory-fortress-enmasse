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

import org.openldap.fortress.DelReviewMgr;
import org.openldap.fortress.DelReviewMgrFactory;
import org.openldap.fortress.SecurityException;
import org.openldap.fortress.rbac.AdminRole;
import org.openldap.fortress.rbac.OrgUnit;
import org.openldap.fortress.rbac.UserAdminRole;
import org.openldap.fortress.rbac.User;
import org.openldap.fortress.rest.FortRequest;
import org.openldap.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
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
        catch (org.openldap.fortress.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}