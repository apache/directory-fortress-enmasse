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

import org.apache.directory.fortress.core.ConfigMgr;
import org.apache.directory.fortress.core.ConfigMgrFactory;
import org.apache.directory.fortress.core.model.Props;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.rest.RestUtils;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.log4j.Logger;

import java.util.Properties;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class ConfigMgrImpl extends AbstractMgrImpl
{
    private static final Logger log = Logger.getLogger( ConfigMgrImpl.class.getName() );

    /**
     *
     * @param request
     * @return
     */
    /* No qualifier */ FortResponse addConfig(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties inProperties = RestUtils.getProperties( (Props)request.getEntity() );
            Properties outProperties = configMgr.add( request.getValue(), inProperties );
            Props retProps = RestUtils.getProps( outProperties );
            
            if ( retProps != null )
            {
                response.setEntity( retProps );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /**
     *
     * @param request
     * @return
     */
    /* No qualifier */ FortResponse updateConfig(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties inProperties = RestUtils.getProperties( (Props)request.getEntity() );
            Properties outProperties = configMgr.update( request.getValue(), inProperties );
            Props retProps = RestUtils.getProps( outProperties );
            
            if ( retProps != null )
            {
                response.setEntity( retProps );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /**
     *
     * @param request
     * @return
     */
    /* No qualifier */ FortResponse deleteConfig(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            
            if ( request.getEntity() == null )
            {
                configMgr.delete( request.getValue() );
            }
            else
            {
                Properties inProperties = RestUtils.getProperties( (Props)request.getEntity() );
                configMgr.delete( request.getValue(), inProperties );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /**
     *
     * @param request
     * @return
     */
    /* No qualifier */ FortResponse readConfig(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            ConfigMgr configMgr = ConfigMgrFactory.createInstance();
            Properties properties = configMgr.read( request.getValue() );
            Props props = RestUtils.getProps( properties );
            
            if ( properties != null )
            {
                response.setEntity( props );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }
}