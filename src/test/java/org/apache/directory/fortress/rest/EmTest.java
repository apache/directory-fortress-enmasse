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
    //private static final String SERVICE = "enmasse-" + VERSION;
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
            String szResponse = post(USER_ID, PASSWORD, "addPermGrant1.xml", HttpIds.ROLE_REVOKE);
            FortResponse response = RestUtils.unmarshall(szResponse);
            int rc = response.getErrorCode();
            String szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_REVOKE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "addEmTestPermission.xml", HttpIds.PERM_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.PERM_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "addEmTestObj1.xml", HttpIds.OBJ_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.OBJ_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "emTestPermOrg1.xml", HttpIds.ORG_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ORG_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "emTestPermOrg1.xml", HttpIds.ORG_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ORG_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "assignEmUser1.xml", HttpIds.ROLE_DEASGN);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_DEASGN + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "delEmUser1.xml", HttpIds.USER_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.USER_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "emTestOrg1.xml", HttpIds.ORG_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ORG_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "emTestOrg1.xml", HttpIds.ORG_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ORG_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "emRoleDelInheritance.xml", HttpIds.ROLE_DELINHERIT);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_DELINHERIT + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "addEmRole1.xml", HttpIds.ROLE_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "delEmRole2.xml", HttpIds.ROLE_DELETE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                // don't fail if the delete was not successful as this may be the first run:
                String warn = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_DELETE + " rc=" + rc + " error message=" + szErrorMsg;
                log.info(warn);
            }

            szResponse = post(USER_ID, PASSWORD, "addEmRole1.xml", HttpIds.ROLE_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "addEmRole2Ascendent.xml", HttpIds.ROLE_ASC);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_ASC + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "addEmUser1.xml", HttpIds.USER_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.USER_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "assignEmUser1.xml", HttpIds.ROLE_ASGN);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_ASGN + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "emTestAuthN.xml", HttpIds.RBAC_AUTHN);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.RBAC_AUTHN + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "createSession.xml", HttpIds.RBAC_CREATE);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.RBAC_AUTHN + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "addEmTestObj1.xml", HttpIds.OBJ_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.OBJ_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "addEmTestPermission.xml", HttpIds.PERM_ADD);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.PERM_ADD + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "addPermGrant1.xml", HttpIds.ROLE_GRANT);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices FAILED calling " + HttpIds.ROLE_GRANT + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

            szResponse = post(USER_ID, PASSWORD, "emTestCheckAccess.xml", HttpIds.RBAC_AUTHZ);
            response = RestUtils.unmarshall(szResponse);
            rc = response.getErrorCode();
            szErrorMsg = response.getErrorMessage();
            if(rc != 0)
            {
                String error = CLS_NM + ".testServices failed calling " + HttpIds.RBAC_AUTHZ + " rc=" + rc + " error message=" + szErrorMsg;
                log.error(error);
            }
            assert(rc == 0);

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
     * Perform an HTTP Post to the configured server.
     *
     * @param userId
     * @param password
     * @param xmlFile
     * @param function
     * @throws RestException
     */
    private String post(String userId, String password, String xmlFile, String function) throws RestException
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
