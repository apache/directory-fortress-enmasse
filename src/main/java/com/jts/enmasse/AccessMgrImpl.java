/*
 * Copyright (c) 2011-2012. Joshua Tree Software, LLC.  All Rights Reserved.
 */
package com.jts.enmasse;

import com.jts.fortress.*;
import com.jts.fortress.SecurityException;
import com.jts.fortress.rbac.Permission;
import com.jts.fortress.rbac.Session;
import com.jts.fortress.rbac.User;
import com.jts.fortress.rbac.UserRole;
import com.jts.fortress.rest.FortRequest;
import com.jts.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.Set;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 * @created February 19, 2012
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
        catch (com.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
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
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}