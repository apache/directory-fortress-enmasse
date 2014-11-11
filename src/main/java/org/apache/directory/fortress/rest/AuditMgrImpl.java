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

import org.apache.directory.fortress.core.AuditMgr;
import org.apache.directory.fortress.core.AuditMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.rbac.AuthZ;
import org.apache.directory.fortress.core.rbac.Bind;
import org.apache.directory.fortress.core.rbac.Mod;
import org.apache.directory.fortress.core.rbac.UserAudit;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
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
        catch (org.apache.directory.fortress.core.SecurityException se)
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