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

import org.openldap.fortress.cfg.ConfigMgr;
import org.openldap.fortress.cfg.ConfigMgrFactory;
import org.openldap.fortress.rbac.Props;
import org.openldap.fortress.rest.FortRequest;
import org.openldap.fortress.rest.FortResponse;
import org.openldap.fortress.rest.RestUtils;
import org.apache.log4j.Logger;

import java.util.Properties;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 */
class ConfigMgrImpl
{
    private static final String CLS_NM = ConfigMgrImpl.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);

    /**
     *
     * @param request
     * @return
     */
    FortResponse addConfig(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties inProperties = RestUtils.getProperties((Props)request.getEntity());
            Properties outProperties = configMgr.add(request.getValue(), inProperties);
            Props retProps = RestUtils.getProps(outProperties);
            if (retProps != null)
            {
                response.setEntity(retProps);
                response.setErrorCode(0);
            }
        }
        catch (org.openldap.fortress.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    /**
     *
     * @param request
     * @return
     */
    FortResponse updateConfig(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties inProperties = RestUtils.getProperties((Props)request.getEntity());
            Properties outProperties = configMgr.update(request.getValue(), inProperties);
            Props retProps = RestUtils.getProps(outProperties);
            if (retProps != null)
            {
                response.setEntity(retProps);
                response.setErrorCode(0);
            }
        }
        catch (org.openldap.fortress.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }

    /**
     *
     * @param request
     * @return
     */
    FortResponse deleteConfig(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            if(request.getEntity() == null)
            {
                configMgr.delete(request.getValue());
            }
            else
            {
                Properties inProperties = RestUtils.getProperties((Props)request.getEntity());
                configMgr.delete(request.getValue(), inProperties);

            }
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

    /**
     *
     * @param request
     * @return
     */
    FortResponse readConfig(FortRequest request)
    {
        FortResponse response = new FortResponse();
        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties properties = configMgr.read(request.getValue());
            Props props = RestUtils.getProps(properties);
            if (properties != null)
            {
                response.setEntity(props);
                response.setErrorCode(0);
            }
        }
        catch (org.openldap.fortress.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}