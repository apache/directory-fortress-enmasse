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

import org.apache.directory.fortress.core.AccessMgr;
import org.apache.directory.fortress.core.AccessMgrFactory;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.rbac.Permission;
import org.apache.directory.fortress.core.rbac.Session;
import org.apache.directory.fortress.core.rbac.User;
import org.apache.directory.fortress.core.rbac.UserRole;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.Set;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 */
class AccessMgrImpl
{
    private static final String CLS_NM = AccessMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN ACCESSMGR
     * **************************************************************************************************************************************
     */

    FortResponse authenticate(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            User inUser = (User) request.getEntity();
            Session outSession = accessMgr.authenticate(inUser.getUserId(), inUser.getPassword());
            response.setSession(outSession);
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

    FortResponse createSession(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            User inUser = (User) request.getEntity();
            Session outSession = accessMgr.createSession(inUser, false);
            response.setSession(outSession);
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

    FortResponse createSessionTrusted(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            User inUser = (User) request.getEntity();
            Session outSession = accessMgr.createSession(inUser, true);
            response.setSession(outSession);
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

    FortResponse checkAccess(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Permission perm = (Permission)request.getEntity();
            perm.setAdmin(false);
            Session session = request.getSession();
            boolean result = accessMgr.checkAccess(session, perm);
            response.setSession(session);
            response.setAuthorized(result);
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

    FortResponse sessionPermissions(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            List<Permission> perms = accessMgr.sessionPermissions(session);
            response.setSession(session);
            response.setEntities(perms);
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

    FortResponse sessionRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            List<UserRole> roles = accessMgr.sessionRoles(session);
            response.setEntities(roles);
            response.setSession(session);
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

    FortResponse authorizedSessionRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            Set<String> roles = accessMgr.authorizedRoles(session);
            response.setValueSet(roles);
            response.setSession(session);
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

    FortResponse addActiveRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            UserRole uRole = (UserRole)request.getEntity();
            Session session = request.getSession();
            accessMgr.addActiveRole(session, uRole);
            response.setSession(session);
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

    FortResponse dropActiveRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            UserRole uRole = (UserRole)request.getEntity();
            Session session = request.getSession();
            accessMgr.dropActiveRole(session, uRole);
            response.setSession(session);
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

    FortResponse getUserId(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            String userId = accessMgr.getUserId(session);
            User outUser = new User(userId);
            response.setSession(session);
            response.setEntity(outUser);
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

    FortResponse getUser(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            AccessMgr accessMgr = AccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            User outUser = accessMgr.getUser(session);
            response.setSession(session);
            response.setEntity(outUser);
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