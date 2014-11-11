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
import org.apache.directory.fortress.core.rbac.AdminRole;
import org.apache.directory.fortress.core.rbac.OrgUnit;
import org.apache.directory.fortress.core.rbac.UserAdminRole;
import org.apache.directory.fortress.core.rbac.User;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
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
        catch (org.apache.directory.fortress.core.SecurityException se)
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