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

import org.apache.directory.fortress.core.cfg.ConfigMgr;
import org.apache.directory.fortress.core.cfg.ConfigMgrFactory;
import org.apache.directory.fortress.core.rbac.Props;
import org.apache.directory.fortress.core.rest.FortRequest;
import org.apache.directory.fortress.core.rest.FortResponse;
import org.apache.directory.fortress.core.rest.RestUtils;
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
        catch (org.apache.directory.fortress.core.SecurityException se)
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
        catch (org.apache.directory.fortress.core.SecurityException se)
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
        catch (org.apache.directory.fortress.core.SecurityException se)
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
        catch (org.apache.directory.fortress.core.SecurityException se)
        {
            log.info(CLS_NM + " caught " + se);
            response.setErrorCode(se.getErrorId());
            response.setErrorMessage(se.getMessage());
        }
        return response;
    }
}