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
import org.apache.directory.fortress.core.GlobalIds;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.util.Config;
import org.apache.directory.fortress.realm.J2eePolicyMgr;
import org.apache.directory.fortress.realm.J2eePolicyMgrFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Grab the Apache Fortress (RBAC) session from Tomcat container via the HttpServletRequest interface. This class is thread safe.
 *
 */
public class SecUtils
{
    private static final Logger LOG = LoggerFactory.getLogger( SecUtils.class.getName() );
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
     * @return Response will contain the RBAC session object (if found) or a system error if a problem in the get.  If arbac02 isn't enabled, it will return a NULL.
     */
    static FortResponse initializeSession(FortRequest fortRequest, HttpServletRequest httpRequest)
    {
        Session realmSession;
        FortResponse fortResponse = null;
        // Have the fortress arbac02 runtime checks been enabled?.
        if (Config.getInstance().getBoolean(GlobalIds.IS_ARBAC02))
        {
            if (httpRequest == null)
            {
                // Improper container config.
                fortResponse = createError( GlobalErrIds.REST_NULL_HTTP_REQ_ERR, "initializeSession detected null HTTP Request", 403);
            }
            else
            {
                try
                {
                    // Get the security principal from the runtime.
                    String szPrincipal = httpRequest.getUserPrincipal().toString();
                    // This has to happen before it can be used by Fortress.
                    realmSession = j2eePolicyMgr.deserialize(szPrincipal);
                    if (realmSession != null)
                    {
                        // The RBAC Session successfully grabbed from the container.
                        fortRequest.setSession(realmSession);
                    }
                    else
                    {
                        fortResponse = createError( GlobalErrIds.USER_SESS_NULL, "initializeSession couldn't get a Security Session.", 403);
                    }
                }
                catch (SecurityException se)
                {
                    // A problem deserializing the security principal.
                    fortResponse = createError( se.getErrorId(), "initializeSession caught SecurityException=" + se.getMessage(), se.getHttpStatus());
                }
            }
        }
        return fortResponse;
    }

    private static FortResponse createError(int errId, String errMsg, int hCode)
    {
        FortResponse fortResponse = new FortResponse();
        fortResponse.setErrorCode(errId);
        fortResponse.setErrorMessage(errMsg);
        fortResponse.setHttpStatus(hCode);
        LOG.info(errMsg);
        return fortResponse;
    }
}
