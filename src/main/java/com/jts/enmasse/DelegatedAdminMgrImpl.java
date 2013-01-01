/*
 * Copyright (c) 2009-2013, JoshuaTree. All Rights Reserved.
 */
package com.jts.enmasse;

import com.jts.fortress.DelAdminMgr;
import com.jts.fortress.DelAdminMgrFactory;
import com.jts.fortress.SecurityException;
import com.jts.fortress.rbac.AdminRole;
import com.jts.fortress.rbac.AdminRoleRelationship;
import com.jts.fortress.rbac.OrgUnit;
import com.jts.fortress.rbac.OrgUnitRelationship;
import com.jts.fortress.rbac.UserAdminRole;
import com.jts.fortress.rest.FortRequest;
import com.jts.fortress.rest.FortResponse;
import org.apache.log4j.Logger;


/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
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
        catch (com.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se + " warnId=" + se.getErrorId());
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se + " errorId=" + se.getErrorId());
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}