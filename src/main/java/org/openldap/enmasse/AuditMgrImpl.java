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

import org.openldap.fortress.AuditMgr;
import org.openldap.fortress.AuditMgrFactory;
import org.openldap.fortress.SecurityException;
import org.openldap.fortress.rbac.AuthZ;
import org.openldap.fortress.rbac.Bind;
import org.openldap.fortress.rbac.Mod;
import org.openldap.fortress.rbac.UserAudit;
import org.openldap.fortress.rest.FortRequest;
import org.openldap.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 */
class AuditMgrImpl
{
    private static final String CLS_NM = AuditMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN AUDIT
     * **************************************************************************************************************************************
     */

    FortResponse searchBinds(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit) request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<Bind> outAudit = auditMgr.searchBinds(inAudit);
            response.setEntities(outAudit);
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

    FortResponse getUserAuthZs(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<AuthZ> outAudit = auditMgr.getUserAuthZs(inAudit);
            response.setEntities(outAudit);
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

    FortResponse searchAuthZs(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<AuthZ> outAudit = auditMgr.searchAuthZs(inAudit);
            response.setEntities(outAudit);
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

    FortResponse searchUserSessions(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<Mod> outAudit = auditMgr.searchUserSessions(inAudit);
            response.setEntities(outAudit);
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

    FortResponse searchAdminMods(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<Mod> outAudit = auditMgr.searchAdminMods(inAudit);
            response.setEntities(outAudit);
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

    FortResponse searchInvalidUsers(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAudit inAudit = (UserAudit)request.getEntity();
            AuditMgr auditMgr = AuditMgrFactory.createInstance(request.getContextId());
            auditMgr.setAdmin(request.getSession());
            List<AuthZ> outAudit = auditMgr.searchInvalidUsers(inAudit);
            response.setEntities(outAudit);
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