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
import org.apache.directory.fortress.core.rbac.AdminRole;
import org.apache.directory.fortress.core.rbac.AdminRoleRelationship;
import org.apache.directory.fortress.core.rbac.OrgUnit;
import org.apache.directory.fortress.core.rbac.OrgUnitRelationship;
import org.apache.directory.fortress.core.rbac.UserAdminRole;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
import org.apache.log4j.Logger;


/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class DelegatedAdminMgrImpl
{
    private static final String CLS_NM = DelegatedAdminMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDADMINMGR
     * **************************************************************************************************************************************
     */

    FortResponse addAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            AdminRole retRole = delegatedAdminMgr.addRole(inRole);
            response.setEntity(retRole);
            response.setErrorCode(0);
        }
        catch (org.apache.directory.fortress.core.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se + " warnId=" + se.getErrorId());
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse deleteAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.deleteRole(inRole);
            response.setEntity(inRole);
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

    FortResponse updateAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRole inRole = (AdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            AdminRole retRole = delegatedAdminMgr.updateRole(inRole);
            response.setEntity(retRole);
            response.setErrorCode(0);
        }
        catch (SecurityException se)
        {
            log.info(CLS_NM + " caught " + se + " errorId=" + se.getErrorId());
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse assignAdminUser(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAdminRole inRole = (UserAdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.assignUser(inRole);
            response.setEntity(inRole);
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

    FortResponse deassignAdminUser(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAdminRole inRole = (UserAdminRole) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.deassignUser(inRole);
            response.setEntity(inRole);
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

    FortResponse addAdminDescendant(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addDescendant(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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

    FortResponse addAdminAscendant(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addAscendant(relationship.getChild(), relationship.getParent());
            response.setEntity(relationship);
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

    FortResponse addAdminInheritance(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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

    FortResponse deleteAdminInheritance(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AdminRoleRelationship relationship = (AdminRoleRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.deleteInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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

    FortResponse addOrg(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            OrgUnit retOrg = delegatedAdminMgr.add(inOrg);
            response.setEntity(retOrg);
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

    FortResponse updateOrg(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            OrgUnit retOrg = delegatedAdminMgr.update(inOrg);
            response.setEntity(retOrg);
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

    FortResponse deleteOrg(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnit inOrg = (OrgUnit) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            OrgUnit retOrg = delegatedAdminMgr.delete(inOrg);
            response.setEntity(retOrg);
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

    FortResponse addOrgDescendant(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addDescendant(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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

    FortResponse addOrgAscendant(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addAscendant(relationship.getChild(), relationship.getParent());
            response.setEntity(relationship);
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

    FortResponse addOrgInheritance(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.addInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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

    FortResponse deleteOrgInheritance(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            OrgUnitRelationship relationship = (OrgUnitRelationship) request.getEntity();
            DelAdminMgr delegatedAdminMgr = DelAdminMgrFactory.createInstance(request.getContextId());
            delegatedAdminMgr.setAdmin(request.getSession());
            delegatedAdminMgr.deleteInheritance(relationship.getParent(), relationship.getChild());
            response.setEntity(relationship);
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