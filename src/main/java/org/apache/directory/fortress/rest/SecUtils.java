//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apache.directory.fortress.rest;

import javax.servlet.http.HttpServletRequest;

import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.realm.J2eePolicyMgr;
import org.apache.directory.fortress.realm.J2eePolicyMgrFactory;
import org.apache.log4j.Logger;

public class SecUtils
{
    private static final Logger LOG = Logger.getLogger(SecUtils.class.getName());

    static FortResponse initializeSession(FortRequest fortRequest, HttpServletRequest httpRequest)
    {
        Session realmSession;
        FortResponse fortResponse = null;

        // If the session is not contained in the request, use the service caller:
        if( fortRequest.getSession() == null)
        {
            if( httpRequest == null)
            {
                fortResponse = new FortResponse();
                fortResponse.setErrorCode(GlobalErrIds.REST_NULL_HTTP_REQ_ERR );
                fortResponse.setErrorMessage( "HTTP Requst is NULL");
            }
            else
            {
                try
                {
                    J2eePolicyMgr j2eePolicyMgr = J2eePolicyMgrFactory.createInstance();
                    String szPrincipal = httpRequest.getUserPrincipal().toString();
                    realmSession = j2eePolicyMgr.deserialize(szPrincipal);
                    if(realmSession != null)
                    {
                        fortRequest.setSession( realmSession );
                    }
                }
                catch (SecurityException se)
                {
                    String error = "intializeSession caught SecurityException=" + se;
                    fortResponse =  new FortResponse();
                    createError(fortResponse, se);
                }
            }
        }
        return fortResponse;
    }

    private static void createError(FortResponse response, SecurityException se )
    {
        LOG.info( "Caught " + se );
        response.setErrorCode( se.getErrorId() );
        response.setErrorMessage( se.getMessage() );
        response.setHttpStatus(se.getHttpStatus());
    }



}
