/*
 * Copyright (c) 2009-2014, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

import java.io.File;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;
import java.util.Collections;

import us.jts.fortress.rest.HttpIds;
import us.jts.fortress.rbac.OrgUnit;
import us.jts.fortress.rbac.PermObj;
import us.jts.fortress.rbac.Permission;
import us.jts.fortress.rbac.Session;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.*;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.io.CachedOutputStream;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.resource.URIResolver;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;


/**
 * Test Client to drive EnMasse Service methods.
 *
 * @author Shawn McKinney
 */
public final class Client
{
    private static final String HOST = "localhost";
    private static final String PORT = "80";
    private static final String SERVICE = "enmasse";
    private static final String URI = "http://" + HOST + ":" + PORT + "/" + SERVICE + "/";

    private Client()
    {
    }

    public static void main(String args[]) throws Exception
    {
        Client client = new Client();


        /*
        client.post("demouser4", "password", "UserSample2.xml", HttpIds.USER_ADD);
        client.delete("demouser4", "password", "fortressUser1", null, null, Services.userDelete.toString());
        client.get("demouser4", "password", "demouser4", null, null, Services.userRead.toString());
        client.get("demouser4", "password", "oamuser1", null, null, Services.userRead.toString());

        client.get("demouser4", "password", "oamRole1", null, null, Services.roleRead.toString());
        client.delete("demouser4", "password", "ROLE_ADMIN", null, null, Services.roleDelete.toString());
        client.post("demouser4", "password", "RoleSample2.xml", Services.roleAdd.toString());
        client.put("demouser4", "password", "RoleSample2Update.xml", Services.roleUpdate.toString());
        client.get("demouser4", "password", "ROLE_ADMIN", null, null, Services.roleRead.toString());
        client.get("demouser4", "password", "role1", null, null, Services.roleRead.toString());
        client.delete("demouser4", "password", "enMasseTestUser1", null, null, Services.userDelete.toString());
        client.post("demouser4", "password", "UserSample2.xml", Services.userAdd.toString());

        client.put("demouser4", "password", "UserSample2Update.xml", Services.userUpdate.toString());

        client.get("demouser4", "password", "enMasseTestUser1", null, null, Services.userRead.toString());

        client.get("demouser4", "password", "USER", "demousrs1", null, Services.orgRead.toString());

        client.findUsers("demouser4", "password", "oam");
        client.findRoles("demouser4", "password", "oam");

        client.delete("demouser4", "password", "USER", "TestEnMasseOrg1", null, Services.orgDelete.toString());
        client.post("demouser4", "password", "TestUserOrg.xml", Services.orgAdd.toString());
        client.get("demouser4", "password", "USER", "TestEnMasseOrg1", null, Services.orgRead.toString());
        client.findOrgs("demouser4", "password", "USER", "o");

        client.delete("demouser4", "password", "USER", "TestEMPermObj1", "read", Services.permDelete.toString());
        client.delete("demouser4", "password", "USER", "TestEMPermObj1", null, Services.objDelete.toString());
        client.delete("demouser4", "password", "PERM", "TestEnMassePermOrg1", null, Services.orgDelete.toString());
        client.post("demouser4", "password", "TestPermOrg.xml", Services.orgAdd.toString());
        client.get("demouser4", "password", "PERM", "TestEnMassePermOrg1", null, Services.orgRead.toString());
        client.post("demouser4", "password", "TestPermObj.xml", Services.objAdd.toString());
        client.get("demouser4", "password", "USER", "TestEMPermObj1", null, Services.objRead.toString());
        client.findPermObjs("demouser4", "password", "USER", "t");

        client.post("demouser4", "password", "TestPermission.xml", Services.permAdd.toString());
        client.get("demouser4", "password", "USER", "TestEMPermObj1", "read", Services.permRead.toString());
        client.findPermissions("demouser4", "password", "USER", "T", "t");

        client.get("demouser4", "password", "demouser4", "password", null, Services.rbacCreate.toString());

        client.post("demouser4", "password", "FUser.xml", Services.userAdd.toString());
        client.post("demouser4", "password", "TestUserAssign.xml", Services.roleAsgn.toString());
        client.get("demouser4", "password", "fortressUser1", null, null, Services.roleAsigned.toString());
        client.post("demouser4", "password", "TestUserDeassign.xml", Services.roleDeasgn.toString());

        client.post("demouser4", "password", "RoleGrant.xml", Services.roleGrant.toString());
        client.post("demouser4", "password", "RoleGrant.xml", Services.roleRevoke.toString());

        client.post("demouser4", "password", "UserGrant.xml", Services.userGrant.toString());
        client.post("demouser4", "password", "UserGrant.xml", Services.userRevoke.toString());

        client.get("demouser4", "password", "oamrole1", null, null, Services.userAsigned.toString());
        client.get("demouser4", "password", "oamrole1", null, null, Services.rolePerms.toString());
        client.get("demouser4", "password", "oamuser1", null, null, Services.userPerms.toString());

        client.put("demouser4", "password", "UserSample2Change.xml", Services.userChange.toString());
        client.get("demouser4", "password", "enMasseTestUser1", null, null, Services.userLock.toString());
        client.get("demouser4", "password", "enMasseTestUser1", null, null, Services.userUnlock.toString());
        client.put("demouser4", "password", "UserSample2Reset.xml", Services.userReset.toString());

        client.delete("demouser4", "password", "ROLE_ADMIN_CHILD", null, null, Services.roleDelete.toString());
        client.post("demouser4", "password", "TestRoleDescendant.xml", Services.roleDescendant.toString());
        client.post("demouser4", "password", "TestRoleDescendant.xml", Services.roleDelinherit.toString());
        client.post("demouser4", "password", "TestRoleDescendant.xml", Services.roleAddinherit.toString());
        client.post("demouser4", "password", "TestRoleDescendant.xml", Services.roleDelinherit.toString());

        client.get("demouser4", "password", "oamT12SSD3", null, null, Services.ssdSets.toString());
        client.get("demouser4", "password", "oamT6Ssd1", null, null, Services.ssdRead.toString());
        client.get("demouser4", "password", "oamT6Ssd1", null, null, Services.ssdRoles.toString());
        client.get("demouser4", "password", "oamT6Ssd1", null, null, Services.ssdCard.toString());
        client.get("demouser4", "password", "oamT12DSD3", null, null, Services.dsdSets.toString());
        client.get("demouser4", "password", "oamT6Dsd1", null, null, Services.dsdRead.toString());
        client.get("demouser4", "password", "oamT6Dsd1", null, null, Services.dsdRoles.toString());
        client.get("demouser4", "password", "oamT6Dsd1", null, null, Services.dsdCard.toString());

        client.get("demouser4", "password", "oamrole1", null, null, Services.roleAuthzed.toString());
        client.get("demouser4", "password", "oamuser1", null, null, Services.userAuthzed.toString());
        client.get("demouser4", "password", "TOB3_3", "TOP3_1", null, Services.permRoles.toString());
        client.get("demouser4", "password", "TOB1_1", "TOP1_1", "001", Services.permRoles.toString());
        client.get("demouser4", "password", "TOB3_3", "TOP3_1", null, Services.permRolesAuthzed.toString());
        client.get("demouser4", "password", "TOB1_1", "TOP1_1", "001", Services.permRolesAuthzed.toString());
        client.get("demouser4", "password", "TOB1_1", "TOP1_1", "001", Services.permUsers.toString());
        client.get("demouser4", "password", "TestEMPermObj1", "read", null, Services.permUsers.toString());
        client.get("demouser4", "password", "TOB3_3", "TOP3_1", null, Services.permUsersAuthzed.toString());
        client.get("demouser4", "password", "TOB1_1", "TOP1_1", "001", Services.permUsersAuthzed.toString());

        client.delete("demouser4", "password", "emSsdT1", null, null, Services.ssdDelete.toString());
        client.delete("demouser4", "password", "SSD_ROLE_1", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "SSD_ROLE_2", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "SSD_ROLE_3", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "SSD_ROLE_4", null, null, Services.roleDelete.toString());
        client.post("demouser4", "password", "RoleSSD1.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleSSD2.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleSSD3.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleSSD4.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "TestCreateSSD.xml", Services.ssdAdd.toString());
        client.get("demouser4", "password", "emSsdT1", "SSD_ROLE_4", null, Services.ssdAddMember.toString());
        client.get("demouser4", "password", "emSsdT1", null, null, Services.ssdRead.toString());
        client.get("demouser4", "password", "emSsdT1", "SSD_ROLE_3", null, Services.ssdDelMember.toString());
        client.get("demouser4", "password", "emSsdT1", "3", null, Services.ssdCardUpdate.toString());
        client.get("demouser4", "password", "emSsdT1", null, null, Services.ssdRead.toString());

        client.delete("demouser4", "password", "emDsdT1", null, null, Services.dsdDelete.toString());
        client.delete("demouser4", "password", "DSD_ROLE_1", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "DSD_ROLE_2", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "DSD_ROLE_3", null, null, Services.roleDelete.toString());
        client.delete("demouser4", "password", "DSD_ROLE_4", null, null, Services.roleDelete.toString());
        client.post("demouser4", "password", "RoleDSD1.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleDSD2.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleDSD3.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "RoleDSD4.xml", Services.roleAdd.toString());
        client.post("demouser4", "password", "TestCreateDSD.xml", Services.dsdAdd.toString());
        client.get("demouser4", "password", "emDsdT1", "DSD_ROLE_4", null, Services.dsdAddMember.toString());
        client.get("demouser4", "password", "emDsdT1", null, null, Services.dsdRead.toString());
        client.get("demouser4", "password", "emDsdT1", "DSD_ROLE_3", null, Services.dsdDelMember.toString());
        client.get("demouser4", "password", "emDsdT1", "3", null, Services.dsdCardUpdate.toString());
        client.get("demouser4", "password", "emDsdT1", null, null, Services.dsdRead.toString());

        client.delete("demouser4", "password", "emPWPolicy1", null, null, Services.pswdDelete.toString());
        client.post("demouser4", "password", "TestPswd.xml", Services.pswdAdd.toString());
        client.get("demouser4", "password", "emPWPolicy1", null, null, Services.pswdRead.toString());
        client.put("demouser4", "password", "TestPswdUpdate.xml", Services.pswdUpdate.toString());
        client.get("demouser4", "password", "emPWPolicy1", null, null, Services.pswdRead.toString());
        client.get("demouser4", "password", "oam", null, null, Services.pswdSearch.toString());
        client.get("demouser4", "password", "enMasseTestUser1", "emPWPolicy1", null, Services.pswdUserAdd.toString());
        client.get("demouser4", "password", "enMasseTestUser1", null, null, Services.pswdUserDelete.toString());

        client.post("demouser4", "password", "TestAdminRoleDescendant.xml", Services.arleDelinherit.toString());
        client.delete("demouser4", "password", "EM_TEST_ADMIN_ROLE_1", null, null, Services.arleDelete.toString());


        client.post("demouser4", "password", "TestAdminRole.xml", Services.arleAdd.toString());
        client.put("demouser4", "password", "TestAdminRoleUpdate.xml", Services.arleUpdate.toString());
        client.get("demouser4", "password", "EM_TEST_ADMIN_ROLE_1", null, null, Services.arleRead.toString());
        client.get("demouser4", "password", "EM", null, null, Services.arleSearch.toString());
        client.get("demouser4", "password", "demouser4", null, null, Services.arleAsigned.toString());
        client.get("demouser4", "password", "oamadmin1", null, null, Services.userAsignedAdmin.toString());

        client.post("demouser4", "password", "AuditBind.xml", Services.auditBinds.toString());


        String szAuthNSession = client.get("demouser4", "password", "demouser4", "password", null, Services.rbacAuthN.toString());
        String szSession = client.get("demouser4", "password", "oamTU3User7", "password7", null, Services.rbacCreate.toString());
        Session session = unmarshallSession(szSession);
        client.checkAccess("demouser4", "password", session, new Permission("TOB3_3", "TOP3_1"));
        szSession = client.dropActiveRole("demouser4", "password", session, new Role("oamT3ROLE4"));
        session = unmarshallSession(szSession);
        szSession = client.addActiveRole("demouser4", "password", session, new Role("oamT3ROLE4"));
        */

        //szSession = marshal(session);
        /*
        client.postStr("demouser4", "password", szSession, Services.rbacPerms.toString());
        client.postStr("demouser4", "password", szSession, Services.rbacRoles.toString());
        client.postStr("demouser4", "password", szSession, Services.rbacUserId.toString());
        client.postStr("demouser4", "password", szSession, Services.rbacUser.toString());
        */


        System.out.println("\n");
        System.exit(0);
    }

    private static Session unmarshallSession(String szSession) throws Exception
    {
        // Create a JAXB context passing in the class of the object we want to marshal/unmarshal
        final JAXBContext context = JAXBContext.newInstance(Session.class);

        // Create the unmarshaller, this is the nifty little thing that will actually transform the XML back into an object
        final Unmarshaller unmarshaller = context.createUnmarshaller();
        return (Session) unmarshaller.unmarshal(new StringReader(szSession));
    }

    private static String marshal(Session session) throws Exception
    {
        // Create a JAXB context passing in the class of the object we want to marshal/unmarshal
        final JAXBContext context = JAXBContext.newInstance(Session.class);
        // =============================================================================================================
        // Marshalling OBJECT to XML
        // =============================================================================================================
        // Create the marshaller, this is the nifty little thing that will actually transform the object into XML
        final Marshaller marshaller = context.createMarshaller();

        // Create a stringWriter to hold the XML
        final StringWriter stringWriter = new StringWriter();
        // Marshal the javaObject and write the XML to the stringWriter
        marshaller.marshal(session, stringWriter);
        return stringWriter.toString();
    }

    public String postStr(String userId, String password, String szInput, String function) throws Exception
    {
        String szResponse = null;
        Client client = new Client();
        // Sent HTTP POST request to add user
        System.out.println("\n");
        System.out.println("Sent HTTP POST request to:" + function);
        //String inputFile = client.getClass().getResource(xmlFile).getFile();
        //URIResolver resolver = new URIResolver(inputFile);
        //File input = new File(resolver.getURI());
        PostMethod post = new PostMethod(URI + function);
        post.addRequestHeader("Accept", "text/xml");
        setMethodHeaders(post, userId, password);
        //RequestEntity entity = new FileRequestEntity(input, "text/xml; charset=ISO-8859-1");
        RequestEntity entity = new StringRequestEntity(szInput, "text/xml; charset=ISO-8859-1", null);
        post.setRequestEntity(entity);
        HttpClient httpclient = new HttpClient();
        try
        {
            int result = httpclient.executeMethod(post);
            System.out.println("Response status code: " + result);
            szResponse = post.getResponseBodyAsString();
            System.out.println(szResponse);
        }
        catch(WebApplicationException we)
        {
            System.out.println("WebApplicationException caught=" + we.getMessage());
        }
        finally
        {
            // Release current connection to the connection pool once you are
            // done
            post.releaseConnection();
        }
        return szResponse;
    }

    public void post(String userId, String password, String xmlFile, String function) throws Exception
    {
        Client client = new Client();
        // Sent HTTP POST request to add user
        System.out.println("\n");
        System.out.println("Sent HTTP POST request to:" + function);
        String inputFile = client.getClass().getResource(xmlFile).getFile();
        URIResolver resolver = new URIResolver(inputFile);
        File input = new File(resolver.getURI());
        PostMethod post = new PostMethod(URI + function);
        post.addRequestHeader("Accept", "text/xml");
        setMethodHeaders(post, userId, password);
        RequestEntity entity = new FileRequestEntity(input, "text/xml; charset=ISO-8859-1");
        post.setRequestEntity(entity);
        HttpClient httpclient = new HttpClient();
        try
        {
            int result = httpclient.executeMethod(post);
            System.out.println("Response status code: " + result);
            System.out.println(post.getResponseBodyAsString());
        }
        catch(WebApplicationException we)
        {
            System.out.println("WebApplicationException caught=" + we.getMessage());
        }
        finally
        {
            // Release current connection to the connection pool once you are
            // done
            post.releaseConnection();
        }
    }

    public void put(String userId, String password, String xmlFile, String function) throws Exception
    {
        Client client = new Client();
        // Sent HTTP POST request to add user
        System.out.println("\n");
        System.out.println("Sent HTTP PUT request to:" + function);
        String inputFile = client.getClass().getResource(xmlFile).getFile();
        URIResolver resolver = new URIResolver(inputFile);
        File input = new File(resolver.getURI());
        PutMethod put = new PutMethod(URI + function);
        put.addRequestHeader("Accept", "text/xml");
        setMethodHeaders(put, userId, password);
        RequestEntity entity = new FileRequestEntity(input, "text/xml; charset=ISO-8859-1");
        put.setRequestEntity(entity);
        HttpClient httpclient = new HttpClient();
        try
        {
            int result = httpclient.executeMethod(put);
            System.out.println("Response status code: " + result);
            System.out.println(put.getResponseBodyAsString());
        }
        catch(WebApplicationException we)
        {
            System.out.println("WebApplicationException caught=" + we.getMessage());
        }
        finally
        {
            // Release current connection to the connection pool once you are
            // done
            put.releaseConnection();
        }
    }

    public void delete(String userId, String password, String id, String id2, String id3, String function) throws Exception
    {
        String url = URI + function + "/" + id;
        if(id2 != null)
        {
            url += "/" + id2;
        }
        if(id3 != null)
        {
            url += "/" + id3;
        }
        System.out.println("HTTP DELETE to query info, url : " + url);
        System.out.println("Deleting now...");
        DeleteMethod del = new DeleteMethod(url);
        //DeleteMethod del = new DeleteMethod(URI + function + "/" + id);
        setMethodHeaders(del, userId, password);
        handleHttpMethod(del);
    }

    public void createSession(String userId, String password, String uid, char[] pw) throws Exception
    {
        String url = URI + HttpIds.RBAC_CREATE + "/" + uid + "/" + pw;
        System.out.println("CREATE SESSION url : " + url);
        GetMethod get = new GetMethod(url);
        setMethodHeaders(get, userId, password);
        handleHttpMethod(get);
    }

    public String get(String userId, String password, String id, String id2, String id3, String function) throws Exception
    {
        String url = URI + function + "/" + id;
        if(id2 != null)
        {
            url += "/" + id2;
        }
        if(id3 != null)
        {
            url += "/" + id3;
        }
        System.out.println("HTTP GET to query info, url : " + url);
        GetMethod get = new GetMethod(url);
        setMethodHeaders(get, userId, password);
        return handleHttpMethod(get);
    }

    private static void setMethodHeaders(HttpMethod httpMethod, String name, String password)
    {
        if (httpMethod instanceof PostMethod || httpMethod instanceof PutMethod)
        {
            httpMethod.setRequestHeader("Content-Type", "application/xml");
            httpMethod.setRequestHeader("Accept", "application/xml");
        }
        //httpMethod.setDoAuthentication(false);
        httpMethod.setDoAuthentication(true);
        httpMethod.setRequestHeader("Authorization",
            "Basic " + base64Encode(name + ":" + password));
    }

    private static String base64Encode(String value)
    {
        return Base64Utility.encode(value.getBytes());
    }

    private static String handleHttpMethod(HttpMethod httpMethod) throws Exception
    {
        HttpClient client = new HttpClient();
        String szResponse = null;

        try
        {
            int statusCode = client.executeMethod(httpMethod);
            System.out.println("Response status : " + statusCode);

            Response.Status status = Response.Status.fromStatusCode(statusCode);

            if (status == Response.Status.OK)
            {
                szResponse = httpMethod.getResponseBodyAsString();
                System.out.println(szResponse);
            }
            else if (status == Response.Status.FORBIDDEN)
            {
                System.out.println("Authorization failure");
            }
            else if (status == Response.Status.UNAUTHORIZED)
            {
                System.out.println("Authentication failure");
            }
            else
            {
                //System.out.println("Unknown error: " + status.toString());
                System.out.println("Unknown error");
            }

            System.out.println();

        }
        finally
        {
            // release any connection resources used by the method
            httpMethod.releaseConnection();
        }
        return szResponse;
    }


    public void findUsers(String userId, String password, String searchVal) throws Exception
    {
        String endpointAddress = URI + HttpIds.USER_SEARCH + "/" + searchVal;
        System.out.println("now hit:" + endpointAddress);

        try
        {
            WebClient wc = WebClient.create(endpointAddress,
                Collections.singletonList(new org.codehaus.jackson.jaxrs.JacksonJsonProvider()));

            String authorizationHeader = "Basic "
                + org.apache.cxf.common.util.Base64Utility.encode(new String(userId + ":" + password).getBytes());
            wc.header("Authorization", authorizationHeader);
            //wc.accept("application/json");
            wc.accept("application/xml");
            Collection<? extends us.jts.fortress.rbac.User> collection = wc.getCollection(us.jts.fortress.rbac.User.class);

            int i = 1;
            for (us.jts.fortress.rbac.User user : collection)
            {
                System.out.println("User[" + i++ + "]");
                System.out.println("    userId: " + user.getUserId());
                System.out.println("    description: " + user.getDescription());
                //System.out.println("    roles: " + user.getRoles());
                System.out.println("    cn: " + user.getCn());
                System.out.println("    sn: " + user.getSn());
                System.out.println("    policy: " + user.getPwPolicy());
                System.out.println("    ou: " + user.getOu());
                System.out.println("    cn: " + user.getCn());
                System.out.println("    beginDate: " + user.getBeginDate());
                System.out.println("    endDate: " + user.getEndDate());
                System.out.println("    beginTime: " + user.getBeginTime());
                System.out.println("    endTime: " + user.getEndTime());
                System.out.println("    beginLockDate: " + user.getBeginLockDate());
                System.out.println("    endLockDate: " + user.getEndLockDate());
                System.out.println("    dayMask: " + user.getDayMask());
                System.out.println("    timeout: " + user.getTimeout());

                if(user.getRoles() != null)
                {
                    int j = 1;
                    for(us.jts.fortress.rbac.UserRole userRole : user.getRoles())
                    {
                        System.out.println("--------------------------------------------------------------------------");
                        System.out.println("User[" + user.getUserId() + "] UserRole[" + j++ + "]");
                        System.out.println("    role name: " + userRole.getName());
                        if(userRole.getParents() != null)
                        {
                            for(String parent : userRole.getParents())
                            {
                                System.out.println("    parent role: " + parent);
                            }
                        }
                        System.out.println("    beginDate: " + userRole.getBeginDate());
                        System.out.println("    endDate: " + userRole.getEndDate());
                        System.out.println("    beginTime: " + userRole.getBeginTime());
                        System.out.println("    endTime: " + userRole.getEndTime());
                        System.out.println("    beginLockDate: " + userRole.getBeginLockDate());
                        System.out.println("    endLockDate: " + userRole.getEndLockDate());
                        System.out.println("    dayMask: " + userRole.getDayMask());
                        System.out.println("    timeout: " + userRole.getTimeout());
                    }
                }
                System.out.println("--------------------------------------------------------------------------");
            }
        }
        catch (Exception e)
        {
            System.out.println("Exception caught in findUsers=" + e);
            e.printStackTrace();
        }
    }


    /**
     * @throws Exception
     */
    public void findRoles(String userId, String password, String searchVal) throws Exception
    {
        String endpointAddress = URI + HttpIds.ROLE_SEARCH + "/" + searchVal;
        System.out.println("now hit:" + endpointAddress);

        try
        {
            WebClient wc = WebClient.create(endpointAddress,
                Collections.singletonList(new org.codehaus.jackson.jaxrs.JacksonJsonProvider()));
            String authorizationHeader = "Basic "
                + org.apache.cxf.common.util.Base64Utility.encode(new String(userId + ":" + password).getBytes());
            wc.header("Authorization", authorizationHeader);
            wc.accept("application/xml");
            Collection<? extends us.jts.fortress.rbac.Role> collection = wc.getCollection(us.jts.fortress.rbac.Role.class);
            for (us.jts.fortress.rbac.Role role : collection)
            {
                System.out.println("Role: " + role.getName() + " description:" + role.getDescription());
                System.out.println("    parents: " + role.getParents());
                System.out.println("    children: " + role.getChildren());
                System.out.println("    beginDate: " + role.getBeginDate());
                System.out.println("    endDate: " + role.getEndDate());
                System.out.println("    beginTime: " + role.getBeginTime());
                System.out.println("    endTime: " + role.getEndTime());
                System.out.println("    beginLockDate: " + role.getBeginLockDate());
                System.out.println("    endLockDate: " + role.getEndLockDate());
                System.out.println("    dayMask: " + role.getDayMask());
                System.out.println("    timeout: " + role.getTimeout());
            }
        }
        catch (Exception e)
        {
            System.out.println("Exception caught in findRoles=" + e);
            e.printStackTrace();
        }
    }


    /**
     * @throws Exception
     */
    public void findOrgs(String userId, String password, String type, String searchVal) throws Exception
    {
        String endpointAddress = URI + HttpIds.ORG_SEARCH + "/" + type + "/" + searchVal;
        System.out.println("now hit:" + endpointAddress);
        try
        {
            WebClient wc = WebClient.create(endpointAddress,
                Collections.singletonList(new org.codehaus.jackson.jaxrs.JacksonJsonProvider()));
            String authorizationHeader = "Basic "
                + org.apache.cxf.common.util.Base64Utility.encode(new String(userId + ":" + password).getBytes());
            wc.header("Authorization", authorizationHeader);
            wc.accept("application/xml");
            Collection<? extends OrgUnit> collection = wc.getCollection(OrgUnit.class);
            for (OrgUnit orgUnit : collection)
            {
                System.out.println("OrgUnit: " + orgUnit.getName() + " description:" + orgUnit.getDescription());
            }
        }
        catch (Exception e)
        {
            System.out.println("Exception caught in searchUserOrgs=" + e);
            e.printStackTrace();
        }
    }


    /**
     * @throws Exception
     */
    public void findPermObjs(String userId, String password, String type, String searchVal) throws Exception
    {
        String endpointAddress = URI + HttpIds.OBJ_SEARCH + "/" + type + "/" + searchVal;
        System.out.println("now hit:" + endpointAddress);
        try
        {
            WebClient wc = WebClient.create(endpointAddress,
                Collections.singletonList(new org.codehaus.jackson.jaxrs.JacksonJsonProvider()));
            String authorizationHeader = "Basic "
                + org.apache.cxf.common.util.Base64Utility.encode(new String(userId + ":" + password).getBytes());
            wc.header("Authorization", authorizationHeader);
            wc.accept("application/xml");
            Collection<? extends PermObj> collection = wc.getCollection(PermObj.class);
            for (PermObj permObj : collection)
            {
                System.out.println("Object Name: " + permObj.getObjName() + " description:" + permObj.getDescription());
            }
        }
        catch (Exception e)
        {
            System.out.println("Exception caught in findPermObjs=" + e);
            e.printStackTrace();
        }
    }


    /**
     * @throws Exception
     */
    public void findPermissions(String userId, String password, String type, String objName, String opName) throws Exception
    {
        String endpointAddress = URI + HttpIds.PERM_SEARCH + "/" + type + "/" + objName + "/" + opName;
        System.out.println("now hit:" + endpointAddress);
        try
        {
            WebClient wc = WebClient.create(endpointAddress,
                Collections.singletonList(new org.codehaus.jackson.jaxrs.JacksonJsonProvider()));
            String authorizationHeader = "Basic "
                + org.apache.cxf.common.util.Base64Utility.encode(new String(userId + ":" + password).getBytes());
            wc.header("Authorization", authorizationHeader);
            wc.accept("application/xml");
            Collection<? extends Permission> collection = wc.getCollection(Permission.class);
            for (Permission perm : collection)
            {
                System.out.println("Permission ObjectName: " + perm.getObjName() + " opName: " + perm.getOpName());
            }
        }
        catch (Exception e)
        {
            System.out.println("Exception caught in findPermissions=" + e);
            e.printStackTrace();
        }
    }


    /**
     * @param in
     * @return
     * @throws Exception
     */
    private static String getStringFromInputStream(InputStream in) throws Exception
    {
        CachedOutputStream bos = new CachedOutputStream();
        IOUtils.copy(in, bos);
        in.close();
        bos.close();
        return bos.getOut().toString();
    }
}
