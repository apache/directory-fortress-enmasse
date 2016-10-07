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

import org.apache.commons.lang.StringUtils;
import org.apache.directory.fortress.core.*;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.model.*;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility for Fortress Rest Server.  This class is thread safe.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class GroupMgrImpl extends AbstractMgrImpl
{
    /** A logger for this class */
    private static final Logger log = Logger.getLogger( GroupMgrImpl.class.getName() );

    
    /* No qualifier */ FortResponse addGroup( FortRequest request )
    {
        FortResponse response = createResponse();
        
        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            Group outGroup = groupMgr.add( inGroup );
            response.setEntity( outGroup );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    /* No qualifier */  FortResponse readGroup( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            Group outGroup = groupMgr.read( inGroup );
            response.setEntity( outGroup );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    
    /* No qualifier */ FortResponse deleteGroup( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            Group outGroup = groupMgr.read( inGroup );
            groupMgr.delete( inGroup );
            response.setEntity( outGroup );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    
    /* No qualifier */ FortResponse updateGroup( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            Group outGroup = groupMgr.update( inGroup );
            response.setEntity( outGroup );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }
        
        return response;
    }

    /* No qualifier */  FortResponse assignedGroups( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Role inRole = (Role) request.getEntity();

            List<Group> groups = groupMgr.roleGroups( inRole );
            response.setEntities( groups );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }


    /* No qualifier */  FortResponse assignedRoles( FortRequest request )
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );

            if ( StringUtils.isNotEmpty( request.getValue() ) )
            {
                String groupName = request.getValue();
                Group outGroup = groupMgr.read( new Group(groupName) );
                List<String> retRoles = new ArrayList<>();
                if ( Group.Type.ROLE.equals( outGroup.getType() ) )
                {
                    retRoles = outGroup.getMembers();
                }
                response.setValues( retRoles );
            }
            else
            {
                Group inGroup = (Group) request.getEntity();
                List<UserRole> uRoles = groupMgr.groupRoles( inGroup );
                response.setEntities( uRoles );
            }
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    /* No qualifier */  FortResponse assignGroup(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            String member = request.getValue();
            groupMgr.assign( inGroup, member );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }

    /* No qualifier */  FortResponse deassignGroup(FortRequest request)
    {
        FortResponse response = createResponse();

        try
        {
            GroupMgr groupMgr = GroupMgrFactory.createInstance( request.getContextId() );
            groupMgr.setAdmin( request.getSession() );
            Group inGroup = (Group) request.getEntity();
            String member = request.getValue();
            groupMgr.deassign( inGroup, member );
        }
        catch ( SecurityException se )
        {
            createError( response, log, se );
        }

        return response;
    }
}