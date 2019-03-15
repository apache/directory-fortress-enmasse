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

import javax.servlet.http.HttpServletRequest;

import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.util.Config;
import org.apache.directory.fortress.realm.J2eePolicyMgr;
import org.apache.directory.fortress.realm.J2eePolicyMgrFactory;
import org.apache.log4j.Logger;


/**
 * Grab the Apache Fortress (RBAC) session from Tomcat container via the HttpServletRequest interface. This class is thread safe.
 *
 */
public class SecUtils
{
    private static final Logger LOG = Logger.getLogger(SecUtils.class.getName());
    private static J2eePolicyMgr j2eePolicyMgr;

    static
    {
        try
        {
            j2eePolicyMgr = J2eePolicyMgrFactory.createInstance();
        }
        catch (SecurityException se)
        {
            String error = "initializeSession caught SecurityException in static block=" + se.getMessage();
            LOG.warn( error );
        }
    }

    /**
     * Use Apache Fortress Realm interface to load the RBAC session via a standard interface.
     *
     * @param fortRequest Used to carry the session and other data.
     * @param httpRequest Used to get the security principal.
     * @return Response containing the RBAC session object if found or error, otherwise (not arbac02 not enabled) return NULL value.
     */
    static FortResponse initializeSession(FortRequest fortRequest, HttpServletRequest httpRequest)
    {
        Session realmSession;
        FortResponse fortResponse = null;
        try
        {
            // Only grab RBAC session from realm if needed for ARBAC02 checks later on.
            if (Config.getInstance().getBoolean("is.arbac02"))
            {
                if (httpRequest == null)
                {
                    fortResponse = new FortResponse();
                    fortResponse.setErrorCode(GlobalErrIds.REST_NULL_HTTP_REQ_ERR);
                    fortResponse.setErrorMessage("initializeSession detected null HTTP Request");
                    fortResponse.setHttpStatus(403);
                }
                else
                {
                    try
                    {
                        String szPrincipal = httpRequest.getUserPrincipal().toString();
                        realmSession = j2eePolicyMgr.deserialize(szPrincipal);
                        if (realmSession != null)
                        {
                            fortRequest.setSession(realmSession);
                        }
                        else
                        {
                            String error = "initializeSession couldn't get a Security Session from the runtime.";
                            fortResponse = new FortResponse();
                            fortResponse.setErrorCode(GlobalErrIds.USER_SESS_NULL);
                            fortResponse.setErrorMessage(error);
                            fortResponse.setHttpStatus(403);
                            LOG.info(error);
                        }
                    }
                    catch (SecurityException se)
                    {
                        String error = "initializeSession caught SecurityException=" + se.getMessage();
                        fortResponse = new FortResponse();
                        LOG.info(error);
                        fortResponse.setErrorCode(se.getErrorId());
                        fortResponse.setErrorMessage(error);
                        fortResponse.setHttpStatus(se.getHttpStatus());
                    }
                }
            }
        }
        catch (java.util.NoSuchElementException e )
        {
            // Means the config property to turn on/off delegated admin checks wasn't present.  Allow the request to continue.
            LOG.info("ARBAC02 checks not enforced on the current request.");
        }
        return fortResponse;
    }
}