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

import org.openldap.fortress.AccessMgr;
import org.openldap.fortress.AccessMgrFactory;
import org.openldap.fortress.SecurityException;
import org.openldap.fortress.rbac.Permission;
import org.openldap.fortress.rbac.Session;
import org.openldap.fortress.rbac.User;
import org.openldap.fortress.rbac.UserRole;
import org.openldap.fortress.rest.FortRequest;
import org.openldap.fortress.rest.FortResponse;
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
        catch (org.openldap.fortress.SecurityException se)
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