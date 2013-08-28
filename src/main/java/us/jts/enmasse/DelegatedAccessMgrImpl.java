/*
 * Copyright (c) 2009-2013, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

import us.jts.fortress.DelAccessMgr;
import us.jts.fortress.DelAccessMgrFactory;
import us.jts.fortress.SecurityException;
import us.jts.fortress.rbac.RolePerm;
import us.jts.fortress.rbac.UserAdminRole;
import us.jts.fortress.rbac.Permission;
import us.jts.fortress.rbac.Role;
import us.jts.fortress.rbac.Session;
import us.jts.fortress.rbac.User;
import us.jts.fortress.rbac.UserRole;
import us.jts.fortress.rest.FortRequest;
import us.jts.fortress.rest.FortResponse;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.Set;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
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
        catch (us.jts.fortress.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
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
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    FortResponse sessionAdminPermissions(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
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

    FortResponse authorizedSessionRoles(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            DelAccessMgr accessMgr = DelAccessMgrFactory.createInstance(request.getContextId());
            Session session = request.getSession();
            Set<String> roles = accessMgr.authorizedAdminRoles(session);
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
}