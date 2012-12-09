/*
 * Copyright (c) 2011-2012. Joshua Tree Software, LLC.  All Rights Reserved.
 */
package com.jts.enmasse;

import com.jts.fortress.DelAccessMgr;
import com.jts.fortress.DelAccessMgrFactory;
import com.jts.fortress.SecurityException;
import com.jts.fortress.rbac.RolePerm;
import com.jts.fortress.rbac.UserAdminRole;
import com.jts.fortress.rbac.Permission;
import com.jts.fortress.rbac.Role;
import com.jts.fortress.rbac.Session;
import com.jts.fortress.rbac.User;
import com.jts.fortress.rbac.UserRole;
import com.jts.fortress.rest.FortRequest;
import com.jts.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 * @created February 19, 2012
 */
class DelegatedAccessMgrImpl
{
    private static final String CLS_NM = DelegatedAccessMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     * ************************************************************************************************************************************
     * BEGIN DELEGATEDACCESSMGR
     * **************************************************************************************************************************************
     */

    FortResponse canAssign(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserRole uRole = (UserRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            boolean result = accessMgr.canAssign(session, new User(uRole.getUserId()), new Role(uRole.getName()));
            response.setSession(session);
            response.setAuthorized(result);
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

    FortResponse canDeassign(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserRole uRole = (UserRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            boolean result = accessMgr.canDeassign(session, new User(uRole.getUserId()), new Role(uRole.getName()));
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

    FortResponse canGrant(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            RolePerm context = (RolePerm) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            boolean result = accessMgr.canGrant(session, new Role(context.getRole().getName()), context.getPerm());
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

    FortResponse canRevoke(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            RolePerm context = (RolePerm) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            boolean result = accessMgr.canRevoke(session, new Role(context.getRole().getName()), context.getPerm());
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

    public FortResponse checkAdminAccess(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            Permission perm = (Permission) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            perm.setAdmin(true);
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

    FortResponse addActiveAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAdminRole uAdminRole = (UserAdminRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            accessMgr.addActiveRole(session, uAdminRole);
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

    FortResponse dropActiveAdminRole(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            UserAdminRole uAdminRole = (UserAdminRole) request.getEntity();
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            accessMgr.dropActiveRole(session, uAdminRole);
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

    FortResponse sessionAdminRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            Session session = request.getSession();
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            List<UserAdminRole> roles = accessMgr.sessionAdminRoles(session);
            response.setEntities(roles);
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