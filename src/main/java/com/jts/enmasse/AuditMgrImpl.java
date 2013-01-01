/*
 * Copyright (c) 2009-2013, JoshuaTree. All Rights Reserved.
 */
package com.jts.enmasse;

import com.jts.fortress.*;
import com.jts.fortress.SecurityException;
import com.jts.fortress.rbac.AuthZ;
import com.jts.fortress.rbac.Bind;
import com.jts.fortress.rbac.Mod;
import com.jts.fortress.rbac.UserAudit;
import com.jts.fortress.rest.FortRequest;
import com.jts.fortress.rest.FortResponse;
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
        catch (com.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}