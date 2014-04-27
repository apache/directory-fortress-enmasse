/*
 * This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2014 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
package org.openldap.enmasse;

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