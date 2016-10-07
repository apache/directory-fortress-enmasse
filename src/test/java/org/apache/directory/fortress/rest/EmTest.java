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

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.directory.fortress.core.RestException;
import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.rest.HttpIds;
import org.apache.directory.fortress.core.rest.RestUtils;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.*;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.helpers.IOUtils;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;


/**
 * Test Client to drive Fortress Rest Service methods.
 *
 * @author Shawn McKinney
 */
public final class EmTest
{
    private static final String CLS_NM = EmTest.class.getName();
    private static final Logger log = Logger.getLogger(CLS_NM);
    private static final String HOST = "localhost";
    private static final String PORT = "8080";
    private static final String VERSION = System.getProperty("version");
    private static final String SERVICE = "fortress-rest-" + VERSION;
    private static final String URI = "http://" + HOST + ":" + PORT + "/" + SERVICE + "/";
    private static final String USER_ID = "demouser4";
    private static final String PASSWORD = "password";

    /**
     * Execute test cases with simple validation.
     *
     */
    @Test
    public void testServices()
    {
        log.info(CLS_NM + ".testServices STARTED");
        try
        {
            // Don't fail if the delete was not successful as this may be the first run:
            testFunction("addPermGrant1.xml", HttpIds.ROLE_REVOKE, false);
            testFunction("delEmGroup1.xml", HttpIds.GROUP_DELETE, false);
            testFunction("addEmTestPermission.xml", HttpIds.PERM_DELETE, false);
            testFunction("addEmTestObj1.xml", HttpIds.OBJ_DELETE, false);
            testFunction("emTestPermOrg1.xml", HttpIds.ORG_DELETE, false);
            testFunction("emTestPermOrg1.xml", HttpIds.ORG_ADD, true);
            testFunction("assignEmUser1.xml", HttpIds.ROLE_DEASGN, false);
            testFunction("delEmUser1.xml", HttpIds.USER_DELETE, false);
            testFunction("emTestOrg1.xml", HttpIds.ORG_DELETE, false);

            testFunction("emTestOrg1.xml", HttpIds.ORG_ADD, true);
            testFunction("emRoleDelInheritance.xml", HttpIds.ROLE_DELINHERIT, false);
            testFunction("addEmRole1.xml", HttpIds.ROLE_DELETE, false);
            testFunction("delEmRole2.xml", HttpIds.ROLE_DELETE, false);
            testFunction("addEmRole3.xml", HttpIds.ROLE_DELETE, false);

            // Create objects and start testing
            testFunction("addEmRole1.xml", HttpIds.ROLE_ADD, true);
            testFunction("addEmRole3.xml", HttpIds.ROLE_ADD, true);
            testFunction("addEmRole2Ascendent.xml", HttpIds.ROLE_ASC, true);
            testFunction("addEmUser1.xml", HttpIds.USER_ADD, true);
            testFunction("assignEmUser1.xml", HttpIds.ROLE_ASGN, true);
            testFunction("emTestAuthN.xml", HttpIds.RBAC_AUTHN, true);
            testFunction("createSession.xml", HttpIds.RBAC_CREATE, true);
            testFunction("addEmTestObj1.xml", HttpIds.OBJ_ADD, true);
            testFunction("addEmTestPermission.xml", HttpIds.PERM_ADD, true);
            testFunction("addPermGrant1.xml", HttpIds.ROLE_GRANT, true);
            testFunction("emTestCheckAccess.xml", HttpIds.RBAC_AUTHZ, true);

            // Create 'emtestgroup1' group with type 'ROLE' and role 'emrole1'
            testFunction("addEmGroup1.xml", HttpIds.GROUP_ADD, true);

            // Read 'emtestgroup1' group by its name
            testFunction("groupRead.xml", HttpIds.GROUP_READ, true);

            // Assign 'emrole3' role for group to check api
            testFunction("assignEmGroup1.xml", HttpIds.GROUP_ASGN, true);

            // Deassign existing 'emrole3' from group
            testFunction("assignEmGroup1.xml", HttpIds.GROUP_DEASGN, true);

            // Read group roles
            testFunction("groupRead.xml", HttpIds.GROUP_ROLE_ASGNED, true);

            // Read groups assigned to 'emrole1' role
            testFunction("addEmRole1.xml", HttpIds.GROUP_ASGNED, true);

            // Create trusted group-based session
            testFunction("createGroupSession.xml", HttpIds.RBAC_CREATE_GROUP_SESSION, true);

            // Use this group session to check access (URL is the same as for user, but session has 'isGroupSession' == true)
            testFunction("emTestCheckAccessGroupSession.xml", HttpIds.RBAC_AUTHZ, true);

            log.info(CLS_NM + ".testServices SUCCESS");
        }
        catch(RestException re)
        {
            String error = CLS_NM + ".post caught RestException=" + re;
            log.error(error);
        }
        log.info(CLS_NM + ".testServices FINISHED");
    }

    /**
     * Performs a request to a given function URL with given filename.
     * @param xmlFile         name of the file (to be searched in resources)
     * @param function url of the REST API function
     * @param failOnError if 'true', will fail on error in API request
     * @throws RestException
     */
    public void testFunction(String xmlFile, String function, boolean failOnError) throws RestException
    {
        String szResponse = post(USER_ID, PASSWORD, xmlFile, function);
        FortResponse response = RestUtils.unmarshall(szResponse);
        int rc = response.getErrorCode();
        String szErrorMsg = response.getErrorMessage();
        String warn = CLS_NM + ".testServices FAILED calling " + function + " rc=" + rc + " error message=" + szErrorMsg;
        if(rc != 0)
        {
            log.info(warn);
        }
        if (failOnError)
        {
            Assert.assertEquals(warn, 0, rc);
        }
    }

    /**
     * Perform an HTTP Post to the configured server.
     *
     * @param userId
     * @param password
     * @param xmlFile
     * @param function
     * @throws RestException
     */
    public String post(String userId, String password, String xmlFile, String function) throws RestException
    {
        String szResponse;
        log.info(CLS_NM + ".post file:" + xmlFile + " HTTP POST request to:" + function);
        URL fUrl = EmTest.class.getClassLoader().getResource(xmlFile);
        PostMethod post = null;
        try
        {
            if(fUrl != null && fUrl.toURI() != null)
            {
                File input = new File(fUrl.toURI());
                post = new PostMethod(URI + function);
                post.addRequestHeader("Accept", "text/xml");
                setMethodHeaders(post, userId, password);
                RequestEntity entity = new FileRequestEntity(input, "text/xml; charset=ISO-8859-1");
                post.setRequestEntity(entity);
                HttpClient httpclient = new HttpClient();
                int result = httpclient.executeMethod(post);
                szResponse = IOUtils.toString(post.getResponseBodyAsStream(), "UTF-8");
                log.info(CLS_NM + ".post Response status code: " + result);
                log.info(CLS_NM + ".post Response value: " + szResponse);
            }
            else
            {
                String error = CLS_NM + ".post input file: " + xmlFile + " not found";
                throw new RestException(GlobalErrIds.REST_IO_ERR, error);
            }

        }
        catch(URISyntaxException ue)
        {
            String error = CLS_NM + ".post caught URISyntaxException=" + ue;
            throw new RestException(GlobalErrIds.REST_IO_ERR, error, ue);
        }
        catch(IOException ie)
        {
            String error = CLS_NM + ".post caught IOException=" + ie;
            throw new RestException(GlobalErrIds.REST_IO_ERR, error, ie);
        }
        catch(WebApplicationException we)
        {
            String error = CLS_NM + ".post caught IOException=" + we;
            throw new RestException(GlobalErrIds.REST_WEB_ERR, error, we);
        }
        finally
        {
            // Release current connection to the connection pool once you are
            // done
            if(post != null)
            {
                post.releaseConnection();
            }
        }
        return szResponse;
    }

    /**
     * Add userId, password to HTTP Basic AuthN header.
     *
     * @param httpMethod
     * @param name
     * @param password
     */
    private static void setMethodHeaders(HttpMethod httpMethod, String name, String password)
    {
        if (httpMethod instanceof PostMethod || httpMethod instanceof PutMethod)
        {
            httpMethod.setRequestHeader("Content-Type", "application/xml");
            httpMethod.setRequestHeader("Accept", "application/xml");
        }
        httpMethod.setDoAuthentication(true);
        httpMethod.setRequestHeader("Authorization",
            "Basic " + base64Encode(name + ":" + password));
    }

    /**
     * Base64 encode a String value.
     *
     * @param value
     * @return
     */
    private static String base64Encode(String value)
    {
        return Base64Utility.encode(value.getBytes());
    }

    /**
     * Main will execute simple test case.
     *
     * @param args
     * @throws Exception
     */
    public static void main(String args[])
     {
         EmTest client = new EmTest();
         client.testServices();
         System.exit(0);
     }

    /**
     *
     */
    public void setUp()
    {
    }

    /**
     *
     */
    public void tearDown()
    {
    }
}
