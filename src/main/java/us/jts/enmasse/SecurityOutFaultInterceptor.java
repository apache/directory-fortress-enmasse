/*
 * Copyright (c) 2009-2014, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.security.AccessDeniedException;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.transport.http.AbstractHTTPDestination;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Utility for EnMasse Server.  This class is thread safe.
 *
 * @author Shawn McKinney
 */

public class SecurityOutFaultInterceptor extends AbstractPhaseInterceptor<Message>
{
    public SecurityOutFaultInterceptor()
    {
        super(Phase.PRE_STREAM);

    }

    public void handleMessage(Message message) throws Fault
    {
        Fault fault = (Fault) message.getContent(Exception.class);
        Throwable ex = fault.getCause();
        if (!(ex instanceof SecurityException))
        {
            throw new RuntimeException("Security Exception is expected:" + ex);
        }

        HttpServletResponse response = (HttpServletResponse) message.getExchange().getInMessage()
            .get(AbstractHTTPDestination.HTTP_RESPONSE);
        int status = ex instanceof AccessDeniedException ? 403 : 401;
        response.setStatus(status);
        try
        {
            response.getOutputStream().write(ex.getMessage().getBytes());
            response.getOutputStream().flush();
        }
        catch (IOException iex)
        {
            // ignore
        }

        message.getInterceptorChain().abort();
    }

}