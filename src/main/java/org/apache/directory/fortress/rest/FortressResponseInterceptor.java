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

import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxrs.interceptor.JAXRSOutInterceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageContentsList;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.directory.fortress.core.model.FortResponse;

/**
 * Interceptor to set the HTTP Status code based on the value present in FortResponse.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FortressResponseInterceptor extends AbstractPhaseInterceptor<Message>
{
    public FortressResponseInterceptor()
    {
        super(Phase.MARSHAL);
        addBefore(JAXRSOutInterceptor.class.getName());
    }
    
    @Override
    public void handleMessage(Message message) throws Fault
    {
        boolean isOutbound = false;
        if( ( message == message.getExchange().getOutMessage() ) || ( message == message.getExchange().getOutFaultMessage() ) )
        {
            isOutbound = true;
        }
        
        if( isOutbound )
        {
            MessageContentsList objs = MessageContentsList.getContentsList(message);
            if (objs != null && !objs.isEmpty())
            {
                Object o = objs.get(0);
                if( o instanceof FortResponse )
                {
                    message.getExchange().put( Message.RESPONSE_CODE, ((FortResponse)o).getHttpStatus() );
                }
            }
        }
    }
}
