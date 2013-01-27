/*
 * Copyright (c) 2009-2013, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

import us.jts.fortress.cfg.ConfigMgr;
import us.jts.fortress.cfg.ConfigMgrFactory;
import us.jts.fortress.rbac.Props;
import us.jts.fortress.rest.FortRequest;
import us.jts.fortress.rest.FortResponse;
import us.jts.fortress.rest.RestUtils;
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
        catch (us.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
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
        catch (us.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
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
        catch (us.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
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
        catch (us.jts.fortress.SecurityException se)
        {
            log.warn("SecurityException=" + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}