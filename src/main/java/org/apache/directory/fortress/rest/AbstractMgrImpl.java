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

import org.apache.log4j.Logger;
import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.FortResponse;

/**
 * An abstract class containing some methods shared by all the implementations.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>

 */
abstract class AbstractMgrImpl
{
    /**
     * Create an error message and log it.
     * 
     * @param response The {@link FortResponse} instance in which we will store the error message and ID
     * @param LOG The Logger
     * @param se The exception
     */
    protected void createError( FortResponse response, Logger LOG, SecurityException se )
    {
        LOG.info( "Caught " + se );
        response.setErrorCode( se.getErrorId() );
        response.setErrorMessage( se.getMessage() );
    }
    
    
    /**
     * Creates a {@link FortResponse} instance where the error code is set with a default value.
     * 
     * @return The created instancd
     */
    protected FortResponse createResponse()
    {
        FortResponse response = new FortResponse();
        response.setErrorCode( GlobalErrIds.NO_ERROR );

        return response;
    }
}
