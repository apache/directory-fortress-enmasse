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

import org.apache.directory.fortress.core.FinderException;
import org.apache.directory.fortress.core.SecurityException;
import org.apache.directory.fortress.core.ValidationException;
import org.apache.directory.fortress.core.model.FortRequest;
import org.apache.directory.fortress.core.model.FortResponse;
import org.apache.directory.fortress.core.model.Group;
import org.apache.directory.fortress.core.model.UserRole;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

/**
 * Interface for Fortress Rest Service methods.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface FortressService
{
    //------------ AdminMgr -----------------------------------------------------------------------------------------------
    /**
     * This command creates a new RBAC user. The command is valid only if the new user is
     * not already a member of the USERS data set. The USER data set is updated. The new user
     * does not own any session at the time of its creation.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * 
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *        <h5>User required parameters</h5>
     *       </li>
     *       <li>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#ou} - contains the name of an already existing 
     *             User OU node
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User optional parameters</h5>
     *       </li>
     *       <li>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#pwPolicy} - contains the name of an already existing 
     *             OpenLDAP password policy node
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#cn} - maps to INetOrgPerson common name 
     *             attribute
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#sn} - maps to INetOrgPerson surname attribute</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#description} - maps to INetOrgPerson description 
     *             attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#phones} * - multi-occurring attribute maps to 
     *             organizationalPerson telephoneNumber  attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#mobiles} * - multi-occurring attribute maps to 
     *             INetOrgPerson mobile attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#emails} * - multi-occurring attribute maps to 
     *             INetOrgPerson mail attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#address} * - multi-occurring attribute maps to 
     *             organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginTime} - HHMM - determines begin hour user 
     *             may activate session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endTime} - HHMM - determines end hour user may 
     *             activate session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginDate} - YYYYMMDD - determines date when user 
     *             may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endDate} - YYYYMMDD - indicates latest date user 
     *             may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginLockDate} - YYYYMMDD - determines beginning 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endLockDate} - YYYYMMDD - determines end of enforced 
     *             inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - 
     *             specifies which day of user may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#timeout} - number in seconds of session inactivity 
     *             time allowed
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} * - multi-occurring attribute contains
     *             property key and values are separated with a ':'.  e.g. mykey1:myvalue1
     *            </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the 
     *             name of already existing role to assign to user
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains 
     *             the name of already existing adminRole to assign to user
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h3>optional parameters</h3>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addUser( FortRequest request );

    
    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * This method performs a "hard" delete.  It completely removes all data associated with this user from the directory.
     * User entity must exist in directory prior to making this call else exception will be thrown.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteUser( FortRequest request );

    
    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * Method performs a "soft" delete.  It performs the following:
     * <ul>
     *   <li>sets the user status to "deleted"</li>
     *   <li>deassigns all roles from the user</li>
     *   <li>locks the user's password in LDAP</li>
     *   <li>revokes all perms that have been granted to user entity.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>  
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse disableUser( FortRequest request );

    
    /**
     * This method performs an update on User entity in directory.  Prior to making this call the entity must exist in
     * directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *       </li>
     *       <li>
     *         <h5>User optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#ou} - contains the name of an already existing User 
     *             OU node
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#pwPolicy} - contains the name of an already existing 
     *             OpenLDAP password policy node
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#cn} - maps to INetOrgPerson common name attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#sn} - maps to INetOrgPerson surname attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#description} - maps to INetOrgPerson description 
     *             attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#phones} * - multi-occurring attribute maps to 
     *             organizationalPerson telephoneNumber  attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#mobiles} * - multi-occurring attribute maps to 
     *             INetOrgPerson mobile attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#emails} * - multi-occurring attribute maps to 
     *             INetOrgPerson mail attribute
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#address} * - multi-occurring attribute maps to 
     *             organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginTime} - HHMM - determines begin hour user may 
     *             activate session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endTime} - HHMM - determines end hour user may 
     *             activate session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginDate} - YYYYMMDD - determines date when user 
     *             may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endDate} - YYYYMMDD - indicates latest date user 
     *             may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#beginLockDate} - YYYYMMDD - determines beginning 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#endLockDate} - YYYYMMDD - determines end of enforced 
     *             inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - 
     *             specifies which day of user may sign on
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#timeout} - number in seconds of session inactivity 
     *             time allowed
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} * - multi-occurring attribute contains property 
     *             key and values are separated with a ':'.  e.g. mykey1:myvalue1
     *           
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the name 
     *             of already existing role to assign to user
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains the 
     *             name of already existing adminRole to assign to user
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateUser( FortRequest request );

    
    /**
     * Method will change user's password.  This method will evaluate user's password policies.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.User} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - contains the User's old password</li>
     *           <li>newPassword - contains the User's new password</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse changePassword( FortRequest request );

    
    /**
     * Method will lock user's password which will prevent the user from authenticating with directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse lockUserAccount( FortRequest request );

    
    /**
     * Method will unlock user's password which will enable user to authenticate with directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse unlockUserAccount( FortRequest request );

    
    /**
     * Method will reset user's password which will require user to change password before successful authentication 
     * with directory.
     * This method will not evaluate password policies on the new user password as it must be changed before use.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>newPassword - contains the User's new password</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse resetPassword( FortRequest request );

    
    /**
     * This command creates a new role. The command is valid if and only if the new role is not
     * already a member of the ROLES data set. The ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to 
     *             be created.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#description} - maps to description attribute on 
     *             organizationalRole object class
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginTime} - HHMM - determines begin hour role may 
     *             be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endTime} - HHMM - determines end hour role may be 
     *             activated into user's RBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginDate} - YYYYMMDD - determines date when role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endDate} - YYYYMMDD - indicates latest date role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginLockDate} - YYYYMMDD - determines beginning 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endLockDate} - YYYYMMDD - determines end of enforced 
     *             inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - 
     *             specifies which day role may be activated into user's RBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addRole( FortRequest request );
    
    
    /**
     * This command deletes an existing role from the RBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ROLES data set.  This command will
     * also deassign role from all users.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             to be removed.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteRole( FortRequest request );

    
    /**
     * Method will update a Role entity in the directory.  The role must exist in role container prior to this call.     *
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to be 
     *             updated.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#description} - maps to description attribute 
     *             on organizationalRole object class
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginTime} - HHMM - determines begin hour role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endTime} - HHMM - determines end hour role may 
     *             be activated into user's RBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginDate} - YYYYMMDD - determines date when role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endDate} - YYYYMMDD - indicates latest date role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#beginLockDate} - YYYYMMDD - determines beginning 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#endLockDate} - YYYYMMDD - determines end of 
     *             enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - 
     *             specifies which day role may be activated into user's RBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *   enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateRole( FortRequest request );

    
    /**
     * This command assigns a user to a role.
     * <ul>
     *   <li> The command is valid if and only if:
     *   <li> The user is a member of the USERS data set
     *   <li> The role is a member of the ROLES data set
     *   <li> The user is not already assigned to the role
     *   <li> The SSD constraints are satisfied after assignment.
     * </ul>
     * Successful completion of this op, the following occurs:
     * <ul>
     *   <li>
     *     User entity (resides in people container) has role assignment added to aux object class attached to actual user 
     *     record.
     *   </li>
     *   <li> Role entity (resides in role container) has userId added as role occupant.</li>
     *   <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:</li>
     *   <li>
     *     <ul>
     *       <li> timeout - number in seconds of session inactivity time allowed.</li>
     *       <li> beginDate - YYYYMMDD - determines date when role may be activated.</li>
     *       <li> endDate - YYMMDD - indicates latest date role may be activated.</li>
     *       <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status</li>
     *       <li> endLockDate - YYMMDD - determines end of enforced inactive status.</li>
     *       <li> beginTime - HHMM - determines begin hour role may be activated in user's session.</li>
     *       <li> endTime - HHMM - determines end hour role may be activated in user's session.*</li>
     *       <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.</li>
     *     </ul>
     *   </li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing 
     *             Role to be assigned
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId for existing User</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserRole optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#beginTime} - HHMM - determines begin hour role 
     *             may be activated into user's RBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#endTime} - HHMM - determines end hour role may 
     *             be activated into user's RBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#beginDate} - YYYYMMDD - determines date when 
     *             role may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#endDate} - YYYYMMDD - indicates latest date role 
     *             may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#beginLockDate} - YYYYMMDD - determines beginning 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#endLockDate} - YYYYMMDD - determines end of 
     *             enforced 
     *             inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - 
     *             specifies which day role may be activated into user's RBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse assignUser( FortRequest request );

    
    /**
     * This command deletes the assignment of the User from the Role entities. The command is
     * valid if and only if the user is a member of the USERS data set, the role is a member of
     * the ROLES data set, and the user is assigned to the role.
     * Any sessions that currently have this role activated will not be effected.
     * Successful completion includes:
     * User entity in USER data set has role assignment removed.
     * Role entity in ROLE data set has userId removed as role occupant.
     * (optional) Temporal constraints will be removed from user aux object if set prior to call.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing
     *             Role to be deassigned
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId for existing 
     *             User
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deassignUser( FortRequest request );

    
    /**
     * This method will add permission operation to an existing permission object which resides under 
     * {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may have {@link org.apache.directory.fortress.core.model.Role} or 
     * {@link org.apache.directory.fortress.core.model.User} associations.  The target 
     * {@link org.apache.directory.fortress.core.model.Permission} must not exist prior to calling.
     * A Fortress Permission instance exists in a hierarchical, one-many relationship between its parent and itself 
     * as stored in ldap tree: ({@link org.apache.directory.fortress.core.model.PermObj}*-&gt;
     * {@link org.apache.directory.fortress.core.model.Permission}).
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Permission required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object 
     *             being targeted for the permission add
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission 
     *             operation being added
     *           </li>
     *         </ul>
     *         <h5>Permission optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#roles} * - multi occurring attribute contains 
     *             RBAC Roles that permission operation is being granted to
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#users} * - multi occurring attribute contains 
     *             Users that permission operation is being granted to
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#props} * - multi-occurring property key and 
     *             values are separated with a ':'.  e.g. mykey1:myvalue1
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.Permission#type} - any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addPermission( FortRequest request );

    
    /**
     * This method will update permission operation pre-existing in target directory under 
     * {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may also contain {@link org.apache.directory.fortress.core.model.Role} 
     * or {@link org.apache.directory.fortress.core.model.User} associations to add or remove using this function.
     * The perm operation must exist before making this call.  Only non-null attributes will be updated.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Permission required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing object 
     *             being targeted for the permission update
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission
     *             operation being updated
     *           </li>
     *         </ul>
     *         <h5>Permission optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#roles} * - multi occurring attribute contains 
     *             RBAC Roles that permission operation is being granted to
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#users} * - multi occurring attribute contains 
     *             Users that permission operation is being granted to
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#props} * - multi-occurring property key and 
     *             values are separated with a ':'.  e.g. mykey1:myvalue1
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.Permission#type} - any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updatePermission( FortRequest request );

    
    /**
     * This method will remove permission operation entity from permission object. A Fortress permission is 
     * (object-&gt;operation).
     * The perm operation must exist before making this call.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Permission required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted for the permission removal
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of new permission 
     *             operation being deleted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deletePermission( FortRequest request );

    
    /**
     * This method will add permission object to perms container in directory. The perm object must not exist before 
     * making this call. A {@link org.apache.directory.fortress.core.model.PermObj} instance exists in a hierarchical, 
     * one-many relationship between itself and children as stored in ldap tree: 
     * ({@link org.apache.directory.fortress.core.model.PermObj}*-&gt;
     * {@link org.apache.directory.fortress.core.model.Permission}).
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermObj required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object being 
     *             added
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#ou} - contains the name of an existing PERMS 
     *             OrgUnit this object is associated with
     *           </li>
     *         </ul>
     *         <h5>PermObj optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermObj#description} - any safe text</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermObj#type} - contains any safe text</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#props} * - multi-occurring property key and 
     *             values are separated with a ':'.  e.g. mykey1:myvalue1
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addPermObj( FortRequest request );

    
    /**
     * This method will update permission object in perms container in directory.  The perm object must exist before making 
     * this call.
     * A {@link org.apache.directory.fortress.core.model.PermObj} instance exists in a hierarchical, one-many relationship 
     * between itself and children as stored in ldap tree: ({@link org.apache.directory.fortress.core.model.PermObj}*-&gt;
     * {@link org.apache.directory.fortress.core.model.Permission}).
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermObj required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object 
     *             being updated
     *           </li>
     *         </ul>
     *         <h5>PermObj optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#ou} - contains the name of an existing PERMS 
     *             OrgUnit this object is associated with
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermObj#description} - any safe text</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermObj#type} - contains any safe text</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#props} * - 
     *             multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service 
     *     will enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updatePermObj( FortRequest request );

    
    /**
     * This method will remove permission object to perms container in directory.  This method will also remove
     * in associated permission objects that are attached to this object.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermObj required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of new object
     *             being removed
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h5>optional parameters</h5>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deletePermObj( FortRequest request );

    
    /**
     * This command grants a role the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the role is a member of the ROLES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermGrant required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#roleNm} - contains the role name</li>
     *         </ul>
     *         <h5>PermGrant optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse grant( FortRequest request );

    
    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a role. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the role is a member of the ROLES data set, and the permission is assigned to that role.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermGrant required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#roleNm} - contains the role name</li>
     *         </ul>
     *         <h5>PermGrant optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse revoke( FortRequest request );

    
    /**
     * This command grants a user the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the user is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermGrant required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermGrant#userId} - contains the userId for existing User
     *           </li>
     *         </ul>
     *         <h5>PermGrant optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse grantUser( FortRequest request );

    
    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a user. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the user is a member of the USERS data set, and the permission is assigned to that user.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermGrant} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>PermGrant required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objName} - contains the object name</li>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#opName} - contains the operation name</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermGrant#userId} - contains the userId for existing User
     *           </li>
     *         </ul>
     *         <h5>PermGrant optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.PermGrant#objId} - contains the object id</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse revokeUser( FortRequest request );

    
    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li> The childRole is not a member of the ROLES data set.
     *   <li> The parentRole is a member of the ROLES data set.
     * </ul>
     * This method:
     * <ul>
     *   <li> Adds new role.
     *   <li> Assigns role relationship between new childRole and pre-existing parentRole.
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of 
     *             existing parent role
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of new 
     *             child role
     *           </li>
     *         </ul>
     *         <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#description} - maps to description 
     *             attribute on organizationalRole object class for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginTime} - HHMM - determines 
     *             begin hour role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endTime} - HHMM - determines end 
     *             hour role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginDate} - YYYYMMDD - determines 
     *             date when role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endDate} - YYYYMMDD - indicates 
     *             latest date role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginLockDate} - YYYYMMDD - 
     *             determines beginning of enforced inactive status for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endLockDate} - YYYYMMDD - 
     *             determines end of enforced inactive status for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday, 
     *             2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addDescendant( FortRequest request );

    
    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li> The parentRole is not a member of the ROLES data set.
     *   <li> The childRole is a member of the ROLES data set.
     * </ul>
     * <p> 
     * This method:
     * <ul>
     *   <li> Adds new role.
     *   <li> Assigns role relationship between new parentRole and pre-existing childRole.
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>childRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains 
     *           the name of existing child Role</li>
     *           <li>parentRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains 
     *           the name of new Role to be parent</li>
     *         </ul>
     *         <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#description} - maps to 
     *             description attribute on organizationalRole object class for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginTime} - HHMM - determines 
     *             begin hour role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endTime} - HHMM - determines 
     *             end hour role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginDate} - YYYYMMDD - 
     *             determines date when role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endDate} - YYYYMMDD - indicates 
     *             latest date role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginLockDate} - YYYYMMDD - 
     *             determines beginning of enforced inactive status for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endLockDate} - YYYYMMDD - 
     *             determines end of enforced inactive status for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 
     *             2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addAscendant( FortRequest request );

    
    /**
     * This commands establishes a new immediate inheritance relationship parentRole &lt;&lt;-- childRole between existing
     * roles parentRole, childRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li> The parentRole and childRole are members of the ROLES data set.
     *   <li> The parentRole is not an immediate ascendant of childRole.
     *   <li> The childRole does not properly inherit parentRole (in order to avoid cycle creation).
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *  <li>
     *    {@link FortRequest#entity} - contains a reference to 
     *    {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *  </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of 
     *             existing role to be parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of 
     *             existing role to be child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addInheritance( FortRequest request );

    
    /**
     * This command deletes an existing immediate inheritance relationship parentRole &lt;&lt;-- childRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The roles parentRole and childRole are members of the ROLES data set.</li>
     *   <li>The parentRole is an immediate ascendant of childRole.</li>
     *   <li> 
     *     The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     *     relation resulted after deleting the relationship parentRole &lt;&lt;-- childRole.
     *   </li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of existing 
     *             Role to remove parent relationship
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of existing 
     *             Role to remove child relationship
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteInheritance( FortRequest request );

    
    /**
     * This command creates a named SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The name of the SSD set is not already in use.</li>
     *   <li>All the roles in the SSD set are members of the ROLES data set.</li>
     *   <li>
     *     n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     *   </li>
     *   <li>The SSD constraint for the new role set is satisfied.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of new SSD role set 
     *             to be added
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains 
     *             the RBAC Role names to be added to this set
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than 
     *             maximum number of Roles that may be assigned to User from a particular set
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse createSsdSet( FortRequest request );

    
    /**
     * This command updates existing SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The name of the SSD set exists in directory.</li>
     *   <li>All the roles in the SSD set are members of the ROLES data set.</li>
     *   <li>
     *    n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     *  </li>
     *   <li>The SSD constraint for the new role set is satisfied.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role 
     *             set to be modified
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains the 
     *             RBAC Role names to be added to this set
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more than 
     *             maximum number of Roles that may be assigned to User from a particular set
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse updateSsdSet( FortRequest request );

    
    /**
     * This command adds a role to a named SSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The SSD role set exists.</li>
     *   <li>The role to be added is a member of the ROLES data set but not of a member of the SSD role set.</li>
     *   <li>The SSD constraint is satisfied after the addition of the role to the SSD role set.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the Role name to add as member to SSD set</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role 
     *             set targeted for update
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse addSsdRoleMember( FortRequest request );

    
    /**
     * This command removes a role from a named SSD set of roles. The cardinality associated with the role set remains
     * unchanged.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The SSD role set exists.</li>
     *   <li>The role to be removed is a member of the SSD role set.</li>
     *   <li>The cardinality associated with the SSD role set is less than the number of elements of the SSD role set.</li>
     * </ul>
     * Note that the SSD constraint should be satisfied after the removal of the role from the SSD role set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the Role name to remove as member to SSD set</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set 
     *             targeted for update
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse deleteSsdRoleMember( FortRequest request );

    
    /**
     * This command deletes a SSD role set completely. The command is valid if and only if the SSD role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role 
     *             set targeted for removal
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse deleteSsdSet( FortRequest request );

    
    /**
     * This command sets the cardinality associated with a given SSD role set.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The SSD role set exists.</li>
     *   <li>
     *     The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of 
     *     elements of the SSD role set.
     *   </li>
     *   <li>The SSD constraint is satisfied after setting the new cardinality.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD role set targeted 
     *             for update
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - contains new cardinality setting 
     *             for SSD
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse setSsdSetCardinality( FortRequest request );

    
    /**
     * This command creates a named DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The name of the DSD set is not already in use.</li>
     *   <li>All the roles in the DSD set are members of the ROLES data set.</li>
     *   <li>
     *     n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     *   </li>
     *   <li>The DSD constraint for the new role set is satisfied.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of new DSD role set to 
     *             be added
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains 
     *             the RBAC Role names to be added to this set
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more 
     *             than maximum number of Roles that may be assigned to User from a particular set
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse createDsdSet( FortRequest request );

    
    /**
     * This command updates existing DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The name of the DSD set exists in directory.</li>
     *   <li>All the roles in the DSD set are members of the ROLES data set.</li>
     *   <li>
     *     n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     *   </li>
     *   <li>The DSD constraint for the new role set is satisfied.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing SSD 
     *             role set to be modified
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#members} * - multi-occurring attribute contains 
     *             the RBAC Role names to be added to this set
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - default is 2 which is one more 
     *             than maximum number of Roles that may be assigned to User from a particular set
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.SDSet#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *     ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse updateDsdSet( FortRequest request );

    
    /**
     * This command adds a role to a named DSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The DSD role set exists.</li>
     *   <li>The role to be added is a member of the ROLES data set but not of a member of the DSD role set.</li>
     *   <li>The DSD constraint is satisfied after the addition of the role to the DSD role set.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the Role name to add as member to DSD set</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role 
     *             set targeted for update
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse addDsdRoleMember( FortRequest request );

    
    /**
     * This command removes a role from a named DSD set of roles. The cardinality associated with the role set remains 
     * unchanged.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The DSD role set exists.</li>
     *   <li>The role to be removed is a member of the DSD role set.</li>
     *   <li>The cardinality associated with the DSD role set is less than the number of elements of the DSD role set.</li>
     * </ul>
     * Note that the DSD constraint should be satisfied after the removal of the role from the DSD role set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the Role name to remove as member to DSD set</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set 
     *             targeted for update
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse deleteDsdRoleMember( FortRequest request );

    
    /**
     * This command deletes a DSD role set completely. The command is valid if and only if the DSD role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role 
     *             set targeted for removal
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse deleteDsdSet( FortRequest request );

    
    /**
     * This command sets the cardinality associated with a given DSD role set.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The DSD role set exists.</li>
     *   <li>
     *     The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of 
     *     elements of the DSD role set.
     *   </li>
     *   <li>The DSD constraint is satisfied after setting the new cardinality.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing DSD role set 
     *             targeted for update
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#cardinality} - contains new cardinality setting for 
     *             DSD
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.SDSet}
     */
    FortResponse setDsdSetCardinality( FortRequest request );


    /**
     * This command enables a role to be constained by attributes.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The role exists.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to
     *             be created.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity2} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleConstraint} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#key} - contains the name of the constraint being set onto role.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity}
     */
    FortResponse enableRoleConstraint( FortRequest request );

    /**
     * This command enables a role to be removed from being constained by attributes.
     * <p>
     * The command is valid if and only if:
     * <ul>
     *   <li>The role exists.</li>
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to removed.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity2} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleConstraint} object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Role required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#key} - contains the name of the constraint being set onto role.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity}
     */
    FortResponse disableRoleConstraint( FortRequest request );

    //------------ ReviewMgr ----------------------------------------------------------------------------------------------
    /**
     * This method returns a matching permission entity to caller.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.Permission}
     */
    FortResponse readPermission( FortRequest request );

    
    /**
     * Method reads permission object from perm container in directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PermObj} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#objName} - contains the name of existing object 
     *             being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.PermObj}
     */
    FortResponse readPermObj( FortRequest request );

    
    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more leading
     *              characters of existing object being targeted
     *            </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains one or more leading 
     *             characters of existing permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.Permission}
     */
    FortResponse findPermissions( FortRequest request );


    /**
     * Method returns Permission operations for the provided permission object.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj}
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more leading 
     *             characters of existing object being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.Permission}
     */
    FortResponse findPermsByObj( FortRequest request );


    /**
     * Method returns a list of type Permission that match any part of either 
     * {@link org.apache.directory.fortress.core.model.Permission#objName} or 
     * {@link org.apache.directory.fortress.core.model.Permission#opName} search strings.
     * This method differs from findPermissions in that any permission that matches any part of the perm obj or any part 
     * of the perm op will be returned in result set (uses substring string matching).
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains one or more substring 
     *             characters of existing object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains one or more substring 
     *             characters of existing permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.Permission}
     */
    FortResponse findAnyPermissions( FortRequest request );


    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PermObj} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PermObj} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PermObj#objName} - contains one or more characters of 
     *             existing object being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.PermObj}
     */
    FortResponse findPermObjs( FortRequest request );

    
    /**
     * Method reads Role entity from the role container in directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role to read.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.Role}
     */
    FortResponse readRole( FortRequest request );

    
    /**
     * Method will return a list of type Role matching all or part of 
     * {@link org.apache.directory.fortress.core.model.Role#name}.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#value} - contains all or some of the chars corresponding to role entities stored in directory.
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.Role}
     */
    FortResponse findRoles( FortRequest request );

    
    /**
     * Method returns matching User entity that is contained within the people container in the directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>
     *            {@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the 
     *            User object targeted for read.
     *          </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse readUser( FortRequest request );

    
    /**
     * Return a list of type User of all users in the people container that match all or part of the 
     * {@link org.apache.directory.fortress.core.model.User#userId} or 
     * {@link org.apache.directory.fortress.core.model.User#ou} fields passed in User entity.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#userId} - contains all or some leading chars that 
     *             match userId(s) stored in the directory.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#ou} - contains one or more characters of org unit 
     *             associated with existing object(s) being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse findUsers( FortRequest request );

    
    /**
     * This method returns the data set of all users who are assigned the given role.  This searches the User data set for
     * Role relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *  <li>
     *    {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *  </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse assignedUsers( FortRequest request );


    /**
     * This method returns the data set of all users who are assigned the given role constraint.  This searches the User data set for
     * RoleConstraint relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *  <li>
     *    {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleConstraint} entity
     *  </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.RoleConstraint} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#key} - contains the name to use for the Role
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#value} - contains the name to use for the Role
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse assignedUsersConstraints( FortRequest request );


    /**
     * This method returns the data set of all users who are assigned the given role constraint.  This searches the User data set for
     * RoleConstraint relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *  <li>
     *    {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RoleConstraint} entity
     *  </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.RoleConstraint} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#type} - contains the name to use for the RoleConstraint type
     *             {@link org.apache.directory.fortress.core.model.RoleConstraint#key} - contains the name to use for the key
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type
     * {@link org.apache.directory.fortress.core.model.UserRole}
     */
    FortResponse assignedUsersConstraintsKey( FortRequest request );


    /**
     * This function returns the set of roles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with 
     *             the User object targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of 
     * type {@link org.apache.directory.fortress.core.model.UserRole}
     */
    FortResponse assignedRoles( FortRequest request );


    /**
     * This function returns the set of users authorized to a given role, i.e., the users that are assigned to a role that
     * inherits the given role. The function is valid if and only if the given role is a member of the ROLES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse authorizedUsers( FortRequest request );

    
    /**
     * This function returns the set of roles authorized for a given user. The function is valid if
     * and only if the user is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the 
     *             User object targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing the User's authorized role names.
     */
    FortResponse authorizedRoles( FortRequest request );

    
    /**
     * Return a list of type String of all roles that have granted a particular permission.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing role names that permission has been granted to.
     */
    FortResponse permissionRoles( FortRequest request );

    
    /**
     * This function returns the set of all permissions (op, obj), granted to or inherited by a
     * given role. The function is valid if and only if the role is a member of the ROLES data
     * set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of 
     * type {@link org.apache.directory.fortress.core.model.Permission} containing permissions for role.
     */
    FortResponse rolePermissions( FortRequest request );

    
    /**
     * This function returns the set of permissions a given user gets through his/her authorized
     * roles. The function is valid if and only if the user is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with the 
     *             User object targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of 
     * type {@link org.apache.directory.fortress.core.model.Permission} containing permissions for user.
     */
    FortResponse userPermissions( FortRequest request );

    
    /**
     * Return all role names that have been authorized for a given permission.  This will process role hierarchies to 
     * determine set of all Roles who have access to a given permission.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing role names that permission has been granted to.
     */
    FortResponse authorizedPermissionRoles( FortRequest request );

    
    /**
     * Return all userIds that have been granted (directly) a particular permission.  This will not consider assigned 
     * or authorized Roles.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing userIds that permission has been granted to.
     */
    FortResponse permissionUsers( FortRequest request );

    
    /**
     * Return all userIds that have been authorized for a given permission.  This will process role hierarchies to determine 
     * set of all Users who have access to a given permission.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing userIds that permission is authorized for.
     */
    FortResponse authorizedPermissionUsers( FortRequest request );

    
    /**
     * This function returns the list of all SSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all SSD role sets.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing all matching SSD sets.
     */
    FortResponse ssdRoleSets( FortRequest request );

    
    /**
     * This function returns the SSD data set that matches a particular set name.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object 
     *             being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing matching SSD set.
     */
    FortResponse ssdRoleSet( FortRequest request );

    
    /**
     * This function returns the set of roles of a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object 
     *             being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing all member roles of SSD set.
     */
    FortResponse ssdRoleSetRoles( FortRequest request );

    
    /**
     * This function returns the cardinality associated with a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>name contains the name of existing SSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    FortResponse ssdRoleSetCardinality( FortRequest request );

    
    /**
     * This function returns the list of all SSD sets that have a particular SSD set name.
     * If the parameter is left blank, function will return all SSD sets.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name to use for the search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing all matching SSD sets.
     */
    FortResponse ssdSets( FortRequest request );

    
    /**
     * This function returns the list of all DSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all DSD role sets.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role 
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing all matching DSD sets.
     */
    FortResponse dsdRoleSets( FortRequest request );

    
    /**
     * This function returns the DSD data set that matches a particular set name.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being 
     *             targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing matching DSD set.
     */
    FortResponse dsdRoleSet( FortRequest request );

    
    /**
     * This function returns the set of roles of a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name of existing object being 
     *             targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type 
     * String containing all member roles of DSD set.
     */
    FortResponse dsdRoleSetRoles( FortRequest request );

    
    /**
     * This function returns the cardinality associated with a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>name contains the name of existing DSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    FortResponse dsdRoleSetCardinality( FortRequest request );

    
    /**
     * This function returns the list of all DSD sets that have a particular DSD set name.
     * If the parameter is left blank, function will return all DSD sets.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.SDSet} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.SDSet} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.SDSet#name} - contains the name to use for the search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.SDSet} containing all matching DSD sets.
     */
    FortResponse dsdSets( FortRequest request );


    //------------ AccessMgr ----------------------------------------------------------------------------------------------
    /**
     * Perform user authentication only.  It does not activate RBAC roles in session but will evaluate
     * password policies.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will be returned if authentication 
     * successful.  This will not contain user's roles.
     */
    FortResponse authenticate( FortRequest request );

    
    /**
     * Perform user authentication {@link org.apache.directory.fortress.core.model.User#password} and role activations.<br>
     * This method must be called once per user prior to calling other methods within this class.
     * The successful result is {@link org.apache.directory.fortress.core.model.Session} that contains target user's RBAC 
     * {@link org.apache.directory.fortress.core.model.User#roles} and Admin role 
     * {@link org.apache.directory.fortress.core.model.User#adminRoles}.<br>
     * In addition to checking user password validity it will apply configured password policy checks 
     * {@link org.apache.directory.fortress.core.model.User#pwPolicy}..<br>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *         </ul>
     *         <h5>User optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the 
     *             names of assigned RBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains 
     *             the names of assigned ARBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected on 
     *             behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>This API will...</h4>
     * <ul>
     *   <li>authenticate user password.</li>
     *   <li>perform <a href="http://www.openldap.org/">OpenLDAP</a> 
     *     <a href="http://tools.ietf.org/html/draft-behera-ldap-password-policy-10">password policy evaluation</a>.
     *   </li>
     *   <li>
     *     fail for any user who is locked by OpenLDAP's policies 
     *     {@link org.apache.directory.fortress.core.model.User#isLocked()}.
     *   </li>
     *   <li>
     *     evaluate temporal {@link org.apache.directory.fortress.core.model.Constraint}(s) on 
     *     {@link org.apache.directory.fortress.core.model.User}, {@link org.apache.directory.fortress.core.model.UserRole} 
     *     and {@link org.apache.directory.fortress.core.model.UserAdminRole} entities.
     *   </li>
     *   <li>
     *     process selective role activations into User RBAC Session 
     *     {@link org.apache.directory.fortress.core.model.User#roles}.
     *   </li>
     *   <li>
     *     check Dynamic Separation of Duties {@link org.apache.directory.fortress.core.impl.DSDChecker#validate} on 
     *     {@link org.apache.directory.fortress.core.model.User#roles}.
     *   </li>
     *   <li>
     *     process selective administrative role activations {@link org.apache.directory.fortress.core.model.User#adminRoles}.
     *   </li>
     *   <li>
     *     return a {@link org.apache.directory.fortress.core.model.Session} containing 
     *     {@link org.apache.directory.fortress.core.model.Session#getUser()}, 
     *     {@link org.apache.directory.fortress.core.model.Session#getRoles()} and (if admin user) 
     *     {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()} if everything checks out good.
     *   </li>
     *   <li>
     *     return a checked exception that will be {@link org.apache.directory.fortress.core.SecurityException} 
     *     or its derivation.
     *   </li>
     *   <li>return a {@link org.apache.directory.fortress.core.SecurityException} for system failures.</li>
     *   <li>
     *     return a {@link org.apache.directory.fortress.core.PasswordException} for authentication and password policy 
     *     violations.
     *   </li>
     *   <li>return a {@link org.apache.directory.fortress.core.ValidationException} for data validation errors.</li>
     *   <li>return a {@link org.apache.directory.fortress.core.FinderException} if User id not found.</li>
     *   <li>(optionally) store parms passed in by client for audit trail purposes.</li>
     * </ul>
     * <h4>The function is valid if and only if:</h4>
     * <ul>
     *   <li>the user is a member of the USERS data set</li>
     *   <li>the password is supplied (unless trusted).</li>
     *   <li>the (optional) active role set is a subset of the roles authorized for that user.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result 
     * code {@link org.apache.directory.fortress.core.model.Session#errorId}, RBAC role activations 
     * {@link org.apache.directory.fortress.core.model.Session#getRoles()}, Admin Role activations 
     * {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()},OpenLDAP pw policy codes 
     * {@link org.apache.directory.fortress.core.model.Session#warnings}, 
     * {@link org.apache.directory.fortress.core.model.Session#expirationSeconds}, 
     * {@link org.apache.directory.fortress.core.model.Session#graceLogins} and more.
     */
    FortResponse createSession( FortRequest request );

    
    /**
     * This service accepts userId for validation and returns RBAC session.  This service will not check the password nor 
     * perform password policy validations.<br>
     * The successful result is {@link org.apache.directory.fortress.core.model.Session} that contains target user's 
     * RBAC {@link org.apache.directory.fortress.core.model.User#roles} and Admin role 
     * {@link org.apache.directory.fortress.core.model.User#adminRoles}.<br>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *         </ul>
     *         <h5>User optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains 
     *             the names of assigned RBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#adminRoles} * - multi-occurring attribute contains 
     *             the names of assigned ARBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected 
     *             on behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>This API will...</h4>
     * <ul>
     *   <li>
     *     fail for any user who is locked by OpenLDAP's policies 
     *     {@link org.apache.directory.fortress.core.model.User#isLocked()}.
     *   </li>
     *   <li>
     *     evaluate temporal {@link org.apache.directory.fortress.core.model.Constraint}(s) on 
     *     {@link org.apache.directory.fortress.core.model.User}, {@link org.apache.directory.fortress.core.model.UserRole} 
     *     and {@link org.apache.directory.fortress.core.model.UserAdminRole} entities.
     *   </li>
     *   <li>
     *     process selective role activations into User RBAC Session 
     *     {@link org.apache.directory.fortress.core.model.User#roles}.
     *   </li>
     *   <li>
     *     check Dynamic Separation of Duties {@link org.apache.directory.fortress.core.impl.DSDChecker#validate} on 
     *     {@link org.apache.directory.fortress.core.model.User#roles}.
     *   </li>
     *   <li>
     *     process selective administrative role activations 
     *     {@link org.apache.directory.fortress.core.model.User#adminRoles}.
     *   </li>
     *   <li>
     *     return a {@link org.apache.directory.fortress.core.model.Session} containing 
     *     {@link org.apache.directory.fortress.core.model.Session#getUser()}, 
     *     {@link org.apache.directory.fortress.core.model.Session#getRoles()} and (if admin user) 
     *     {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()} if everything checks out good.
     *   </li>
     *   <li>
     *     return a checked exception that will be {@link org.apache.directory.fortress.core.SecurityException} or 
     *     its derivation.
     *   </li>
     *   <li>return a {@link org.apache.directory.fortress.core.SecurityException} for system failures.</li>
     *   <li>return a {@link org.apache.directory.fortress.core.ValidationException} for data validation errors.</li>
     *   <li>return a {@link org.apache.directory.fortress.core.FinderException} if User id not found.</li>
     *   <li>(optionally) store parms passed in by client for audit trail purposes.</li>
     * </ul>
     * <h4>The function is valid if and only if:</h4>
     * <ul>
     *   <li> the user is a member of the USERS data set</li>
     *   <li> the (optional) active role set is a subset of the roles authorized for that user.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result 
     * code {@link org.apache.directory.fortress.core.model.Session#errorId}, RBAC role activations 
     * {@link org.apache.directory.fortress.core.model.Session#getRoles()}, Admin Role activations 
     * {@link org.apache.directory.fortress.core.model.Session#getAdminRoles()},OpenLDAP pw policy codes 
     * {@link org.apache.directory.fortress.core.model.Session#warnings}, 
     * {@link org.apache.directory.fortress.core.model.Session#expirationSeconds}, 
     * {@link org.apache.directory.fortress.core.model.Session#graceLogins} and more.
     */
    FortResponse createSessionTrusted( FortRequest request );

    /**
     * Perform group {@link Group} role activations {@link Group#members}.<br>
     * Group sessions are always trusted. <br>
     * This method must be called once per group prior to calling other methods within this class.
     * The successful result is {@link org.apache.directory.fortress.core.model.Session} that contains target group's RBAC
     * {@link Group#members}
     * <h3></h3>
     * <h4>This API will...</h4>
     * <ul>
     *   <li>
     *     fail for any non-existing group
     *   </li>
     *   <li>
     *     evaluate temporal {@link org.apache.directory.fortress.core.model.Constraint}(s) on member {@link UserRole} entities.
     *   <li>process selective role activations into Group RBAC Session {@link Group#roles}.</li>
     *   <li>
     *     check Dynamic Separation of Duties {@link org.apache.directory.fortress.core.impl.DSDChecker#validate(
     *          org.apache.directory.fortress.core.model.Session,
     *          org.apache.directory.fortress.core.model.Constraint,
     *          org.apache.directory.fortress.core.util.time.Time,
     *          org.apache.directory.fortress.core.util.VUtil.ConstraintType)} on
     *          {@link org.apache.directory.fortress.core.model.User#roles}.
     *   </li>
     *   <li>
     *     return a {@link org.apache.directory.fortress.core.model.Session} containing
     *     {@link org.apache.directory.fortress.core.model.Session#getGroup()},
     *     {@link org.apache.directory.fortress.core.model.Session#getRoles()}
     *   </li>
     *   <li>throw a checked exception that will be {@link SecurityException} or its derivation.</li>
     *   <li>throw a {@link SecurityException} for system failures.</li>
     *   <li>throw a {@link ValidationException} for data validation errors.</li>
     *   <li>throw a {@link FinderException} if Group name not found.</li>
     * </ul>
     * <h4>
     * The function is valid if and only if:
     * </h4>
     * <ul>
     *   <li> the group is a member of the GROUPS data set</li>
     *   <li> the (optional) active role set is a subset of the roles authorized for that group.</li>
     * </ul>
     * <h4>
     * The following attributes may be set when calling this method
     * </h4>
     * <ul>
     *   <li>{@link Group#name} - required</li>
     *   <li>
     *     {@link org.apache.directory.fortress.core.model.Group#members} contains a list of RBAC role names authorized for group
     *     and targeted for activation within this session.  Default is all authorized RBAC roles will be activated into this
     *     Session.
     *   </li>
     * </ul>
     * <h4>
     * Notes:
     * </h4>
     * <ul>
     * <li> roles that violate Dynamic Separation of Duty Relationships will not be activated into session.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * (optional), optional {@link Group#type}, optional
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result
     * {@link org.apache.directory.fortress.core.model.Session#errorId},
     * RBAC role activations {@link org.apache.directory.fortress.core.model.Session#getRoles()},
     * OpenLDAP pw policy codes {@link org.apache.directory.fortress.core.model.Session#warnings},
     * {@link org.apache.directory.fortress.core.model.Session#expirationSeconds},
     * {@link org.apache.directory.fortress.core.model.Session#graceLogins} and more.
     */
    FortResponse createGroupSession(FortRequest request );

    
    /**
     * Perform user RBAC authorization.  This function returns a Boolean value meaning whether the subject of a given 
     * session is allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission} 
     *     entity
     *   </li>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User 
     * authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse checkAccess( FortRequest request );


    /**
     * Combine createSession and checkAccess into a single method.
     * This function returns a Boolean value meaning whether the User is allowed or not to perform a given operation on a given object.
     * The function is valid if and only if the user is a valid Fortress user, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The user has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the user's active roles are registered in the object's access control list.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Permission}
     *     entity
     *   </li>
     *   <li>
     *     {@link FortRequest#entity2} - contains a reference to User object containing userId.
     *   </li>
     *   <li>
     *     {@link FortRequest#isFlag} - boolean value if true, password check will not be performed.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing
     *             object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *         </ul>
     *         <h5>User optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the
     *             names of assigned RBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected on
     *             behalf of User during signon.  For example locale:east
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User
     * authorized, otherwise 'false'.
     */
    FortResponse createSessionCheckAccess( FortRequest request );


    /**
     * Combine createSession and a role check into a single method.
     * This function returns a Boolean value meaning whether the User has a particular role.
     * The function is valid if and only if the user is a valid Fortress user and the role is a member of the ROLES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role}
     *     entity
     *   </li>
     *   <li>
     *     {@link FortRequest#entity2} - contains a reference to User object containing userId.
     *   </li>
     *   <li>
     *     {@link FortRequest#isFlag} - boolean value if true, password check will not be performed.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name of existing
     *             role being targeted for check.
     *           </li>
     *         </ul>
     *       </li>
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.User#userId} - maps to INetOrgPerson uid</li>
     *           <li>{@link org.apache.directory.fortress.core.model.User#password} - used to authenticate the User</li>
     *         </ul>
     *         <h5>User optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#roles} * - multi-occurring attribute contains the
     *             names of assigned RBAC roles targeted for activation into Session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#props} collection of name value pairs collected on
     *             behalf of User during signon.  For example locale:east
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User
     * authorized, otherwise 'false'..
     */
    FortResponse isUserInRole( FortRequest request );


    /**
     * This function returns the permissions of the session, i.e., the permissions assigned
     * to its authorized roles. The function is valid if and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *   {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type 
     * {@link org.apache.directory.fortress.core.model.Permission}.  Updated {@link FortResponse#session} will be included 
     * in response as well.
     */
    FortResponse sessionPermissions( FortRequest request );

    
    /**
     * This function returns the active roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type 
     * {@link org.apache.directory.fortress.core.model.UserRole}.  Updated {@link FortResponse#session} will be included 
     * in response as well.
     */
    FortResponse sessionRoles( FortRequest request );

    
    /**
     * This function returns the authorized roles associated with a session based on hierarchical relationships. The 
     * function is valid if and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String containing 
     * role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse authorizedSessionRoles( FortRequest request );

    
    /**
     * This function adds a role as an active role of a session whose owner is a given user.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for 
     *             activation into User's session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     *   <li>the user is a member of the USERS data set</li>
     *   <li>the role is a member of the ROLES data set</li>
     *   <li>the role inclusion does not violate Dynamic Separation of Duty Relationships</li>
     *   <li>the session is a valid Fortress session</li>
     *   <li>the user is authorized to that role</li>
     *   <li>the session is owned by that user.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    FortResponse addActiveRole( FortRequest request );

    
    /**
     * This function deletes a role from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the role is an active role of that session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for 
     *             removal from User's session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    FortResponse dropActiveRole( FortRequest request );

    
    /**
     * This function returns the userId value that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to 
     * {@link org.apache.directory.fortress.core.model.User#userId} only.
     */
    FortResponse getUserId( FortRequest request );

    
    /**
     * This function returns the user object that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to 
     * {@link org.apache.directory.fortress.core.model.User}.
     */
    FortResponse getUser( FortRequest request );


    //------------ DelegatedAdminMgr --------------------------------------------------------------------------------------
    /**
     * This command creates a new admin role. The command is valid if and only if the new admin role is not
     * already a member of the ADMIN ROLES data set. The ADMIN ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>AdminRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole 
     *             being targeted for addition to LDAP
     *           </li>
     *         </ul>
     *         <h5>AdminRole optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.AdminRole#description} - contains any safe text</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#osPs} * - multi-occurring attribute used to 
     *             set associations to existing PERMS OrgUnits
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#osUs} * - multi-occurring attribute used to 
     *             set associations to existing USERS OrgUnits
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginRange} - contains the name of an existing 
     *             RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole 
     *             activated) controls
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endRange} - contains the name of an existing 
     *             RBAC Role that represents that highest role in hierarchy that administrator may control
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginInclusive} - if 'true' the RBAC Role 
     *             specified in beginRange is also controlled by the posessor of this AdminRole
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endInclusive} - if 'true' the RBAC Role 
     *             specified in endRange is also controlled by the administratrator
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginTime} - HHMM - determines begin hour 
     *             adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endTime} - HHMM - determines end hour adminRole 
     *             may be activated into user's ARBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginDate} - YYYYMMDD - determines date when 
     *             adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endDate} - YYYYMMDD - indicates latest date 
     *             adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginLockDate} - YYYYMMDD - determines 
     *             beginning of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endLockDate} - YYYYMMDD - determines end 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, 
     *             etc - specifies which day role may be activated into user's ARBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a 
     * {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    FortResponse addAdminRole( FortRequest request );

    
    /**
     * This command deletes an existing admin role from the ARBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ADMIN ROLES data set.  This command will
     * also deassign role from all users.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>AdminRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole 
     *             being targeted for removal from LDAP
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a 
     * {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    FortResponse deleteAdminRole( FortRequest request );

    
    /**
     * Method will update an AdminRole entity in the directory.  The role must exist in directory prior to this call.     *
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>AdminRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the new AdminRole 
     *             being targeted for update to LDAP
     *           </li>
     *         </ul>
     *         <h5>AdminRole optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.AdminRole#description} - contains any safe text</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#osPs} * - multi-occurring attribute used to set 
     *             associations to existing PERMS OrgUnits
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#osUs} * - multi-occurring attribute used to set 
     *             associations to existing USERS OrgUnits
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginRange} - contains the name of an existing 
     *             RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole 
     *             activated) controls
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endRange} - contains the name of an existing 
     *             RBAC Role that represents that highest role in hierarchy that administrator may control
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginInclusive} - if 'true' the RBAC Role 
     *             specified in beginRange is also controlled by the posessor of this AdminRole
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endInclusive} - if 'true' the RBAC Role 
     *             specified in endRange is also controlled by the administratrator
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginTime} - HHMM - determines begin hour 
     *             adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endTime} - HHMM - determines end hour 
     *             adminRole may be activated into user's ARBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginDate} - YYYYMMDD - determines date 
     *             when adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endDate} - YYYYMMDD - indicates latest date 
     *             adminRole may be activated into user's ARBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#beginLockDate} - YYYYMMDD - determines 
     *             beginning of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#endLockDate} - YYYYMMDD - determines end 
     *             of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, 
     *             etc - specifies which day role may be activated into user's ARBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a 
     * {@link org.apache.directory.fortress.core.model.AdminRole}.
     */
    FortResponse updateAdminRole( FortRequest request );

    
    /**
     * This command assigns a user to an administrative role.
     * <ul>
     *   <li> The command is valid if and only if:
     *   <li> The user is a member of the USERS data set
     *   <li> The role is a member of the ADMIN ROLES data set
     *   <li> The user is not already assigned to the admin role
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserAdminRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the name for already 
     *             existing AdminRole to be assigned
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#userId} - contains the userId for 
     *             existing User
     *           </li>
     *         </ul>
     *         <h5>UserAdminRole optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#beginTime} - HHMM - determines begin 
     *             hour AdminRole may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#endTime} - HHMM - determines end hour 
     *             AdminRole may be activated into user's RBAC session.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#beginDate} - YYYYMMDD - determines date 
     *             when AdminRole may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#endDate} - YYYYMMDD - indicates latest 
     *             date AdminRole may be activated into user's RBAC session
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#beginLockDate} - YYYYMMDD - determines 
     *             beginning of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#endLockDate} - YYYYMMDD - determines 
     *             end of enforced inactive status
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#dayMask} - 1234567, 1 = Sunday, 
     *             2 = Monday, etc - specifies which day role may be activated into user's ARBAC session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * <p>
     * Successful completion of this op, the following occurs:
     * <ul>
     *   <li>
     *     User entity (resides in people container) has role assignment added to aux object class attached to actual 
     *     user record.
     *   </li>
     *   <li> AdminRole entity (resides in adminRole container) has userId added as role occupant.</li>
     *   <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:</li>
     *   <li>
     *     <ul>
     *       <li> timeout - number in seconds of session inactivity time allowed.</li>
     *       <li> beginDate - YYYYMMDD - determines date when role may be activated.</li>
     *       <li> endDate - YYMMDD - indicates latest date role may be activated.</li>
     *       <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status</li>
     *       <li> endLockDate - YYMMDD - determines end of enforced inactive status.</li>
     *       <li> beginTime - HHMM - determines begin hour role may be activated in user's session.</li>
     *       <li> endTime - HHMM - determines end hour role may be activated in user's session.*</li>
     *       <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.</li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse assignAdminUser( FortRequest request );

    
    /**
     * This method removes assigned admin role from user entity.  Both user and admin role entities must exist and have 
     * role relationship before calling this method.
     * <p>
     * Successful completion :<br>
     * del Role to User assignment in User data set<br>
     * AND<br>
     * User to Role assignment in Admin Role data set.<br>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserAdminRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the name for already 
     *             existing AdminRole to be deassigned
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#userId} - contains the userId for existing 
     *             User
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deassignAdminUser( FortRequest request );

    
    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole. The command is valid if and only if childRole is not a member of the ADMINROLES data 
     * set, and parentRole is a member of the ADMINROLES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of 
     *             existing parent role
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of new 
     *             child role
     *           </li>
     *         </ul>
     *         <h5>optional parameters {@code org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#description} - maps to description 
     *             attribute on organizationalRole object class for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginTime} - HHMM - determines 
     *             begin hour role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endTime} - HHMM - determines end 
     *             hour role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginDate} - YYYYMMDD - determines 
     *             date when role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endDate} - YYYYMMDD - indicates 
     *             latest date role may be activated into user's RBAC session for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#beginLockDate} - YYYYMMDD - 
     *             determines beginning of enforced inactive status for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#endLockDate} - YYYYMMDD - 
     *             determines end of enforced inactive status for new child
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday,
     *              2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The childRole is not a member of the ADMINROLES data set.</li>
     *   <li>The parentRole is a member of the ADMINROLES data set.</li>
     * </ul>
     * <p> 
     * This method:
     * <ul>
     *   <li>Adds new adminRole.</li>
     *   <li>Assigns role relationship between new childRole and pre-existing parentRole.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addAdminDescendant( FortRequest request );

    
    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole. The command is valid if and only if parentRole is not a member of the ADMINROLES data set,
     * and childRole is a member of the ADMINROLES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             childRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the 
     *             name of existing child AdminRole</li>
     *           <li>
     *             parentRole - {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the 
     *             name of new AdminRole to be parent</li>
     *         </ul>
     *         <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#description} - maps to description 
     *             attribute on organizationalRole object class for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginTime} - HHMM - determines 
     *             begin hour role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endTime} - HHMM - determines end 
     *             hour role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginDate} - YYYYMMDD - 
     *             determines date when role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endDate} - YYYYMMDD - indicates 
     *             latest date role may be activated into user's RBAC session for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#beginLockDate} - YYYYMMDD - 
     *             determines beginning of enforced inactive status for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#endLockDate} - YYYYMMDD - 
     *             determines end of enforced inactive status for new parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 
     *             2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The parentRole is not a member of the ADMINROLES data set.</li>
     *   <li>The childRole is a member of the ADMINROLES data set.</li>
     * </ul>
     * This method:
     * <ul>
     *   <li>Adds new adminRole.</li>
     *   <li>Assigns role relationship between new parentRole and pre-existing childRole.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addAdminAscendant( FortRequest request );

    
    /**
     * This commands establishes a new immediate inheritance relationship parentRole &lt;&lt;-- childRole between existing
     * roles parentRole, childRole. The command is valid if and only if parentRole and childRole are members of the 
     * ADMINROLES data set, parentRole is not an immediate ascendant of childRole, and childRole does not properly 
     * inherit parentRole (in order to avoid cycle creation).
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name 
     *             of existing AdminRole to be parent
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of 
     *             existing AdminRole to be child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The parentRole and childRole are members of the ADMINROLES data set.</li>
     *   <li>The parentRole is not an immediate ascendant of childRole.</li>
     *   <li>The childRole does not properly inherit parentRole (in order to avoid cycle creation).</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addAdminInheritance( FortRequest request );

    
    /**
     * This command deletes an existing immediate inheritance relationship parentRole &lt;&lt;-- childRole. The command is
     * valid if and only if the adminRoles parentRole and childRole are members of the ADMINROLES data set, and parentRole 
     * is an immediate ascendant of childRole. The new inheritance relation is computed as the reflexive-transitive
     * closure of the immediate inheritance relation resulted after deleting the relationship parentRole &lt;&lt;-- childRole.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.RoleRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>RoleRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#parent#name} - contains the name of 
     *             existing Role to remove parent relationship
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RoleRelationship#child#name} - contains the name of
     *             existing Role to remove child relationship
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The roles parentRole and childRole are members of the ADMINROLES data set.</li>
     *   <li>The parentRole is an immediate ascendant of childRole.</li>
     *   <li>
     *     The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     *     relation resulted after deleting the relationship parentRole &lt;&lt;-- childRole.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteAdminInheritance( FortRequest request );

    
    /**
     * Commands adds a new OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnit required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of new USERS or 
     *             PERMS OrgUnit to be added
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *         </ul>
     *         <h5>OrgUnit optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.OrgUnit#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addOrg( FortRequest request );

    
    /**
     * Commands updates existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnit required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of USERS or PERMS 
     *             OrgUnit to be updated
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *         </ul>
     *         <h5>OrgUnit optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.OrgUnit#description} - contains any safe text</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateOrg( FortRequest request );

    
    /**
     * Commands deletes existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnit required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name of USERS or 
     *             PERMS OrgUnit to be removed
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteOrg( FortRequest request );

    
    /**
     * This commands creates a new orgunit child, and inserts it in the orgunit hierarchy as an immediate descendant of
     * the existing orgunit parent.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnitRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - 
     *             contains the name of existing OrgUnit to be parent
     *           </li>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - 
     *             contains the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER}
     *             or {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - 
     *             contains the name of new OrgUnit to be child
     *           </li>
     *         </ul>
     *         <h5>optional parameters {@code org.apache.directory.fortress.core.model.RoleRelationship#child}</h5>
     *         <ul>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#description} - maps 
     *             to description attribute on organizationalUnit object class for new child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The child orgunit is not a member of the ORGUNITS data set.</li>
     *   <li>The parent orgunit is a member of the ORGUNITS data set.</li>
     * </ul>
     * This method:
     * <ul>
     *   <li>Adds new orgunit.</li>
     *   <li>Assigns orgunit relationship between new child and pre-existing parent.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addOrgDescendant( FortRequest request );

    
    /**
     * This commands creates a new orgunit parent, and inserts it in the orgunit hierarchy as an immediate ascendant of
     * the existing child orgunit.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnitRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains 
     *             the name of existing OrgUnit to be child
     *           </li>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#type} - contains 
     *             the type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains 
     *             the name of new OrgUnit to be parent
     *           </li>
     *         </ul>
     *         <h5>optional parameters {@link org.apache.directory.fortress.core.model.RoleRelationship#parent}</h5>
     *         <ul>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#description} -
     *             maps to description attribute on organizationalUnit object class for new parent
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The parent is not a member of the ORGUNITS data set.</li>
     *   <li>The child is a member of the ORGUNITS data set.</li>
     * </ul>
     * This method:
     * <ul>
     *   <li>Adds new orgunit.</li>
     *   <li>Assigns orgunit relationship between new parent and pre-existing child.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addOrgAscendant( FortRequest request );

    
    /**
     * This commands establishes a new immediate inheritance relationship with parent orgunit &lt;&lt;-- child orgunit
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnitRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the 
     *             name of existing OrgUnit to be parent
     *           </li>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - contains the 
     *             type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the 
     *             name of new OrgUnit to be child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The parent and child are members of the ORGUNITS data set.</li>
     *   <li>The parent is not an immediate ascendant of child.</li>
     *   <li>The child does not properly inherit parent (in order to avoid cycle creation).</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addOrgInheritance( FortRequest request );

    
    /**
     * This command deletes an existing immediate inheritance relationship parent &lt;&lt;-- child.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.OrgUnitRelationship} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>OrgUnitRelationship required parameters</h5>
     *         <ul>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#name} - contains the 
     *             name of existing OrgUnit to remove as parent
     *           </li>
     *           <li>
     *             parent - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#parent#type} - contains the 
     *             type of OrgUnit targeted: {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *           <li>
     *             child - {@code org.apache.directory.fortress.core.model.OrgUnitRelationship#child#name} - contains the 
     *             name of new OrgUnit to remove as child
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     *   <li>The orgunits parent and child are members of the ORGUNITS data set.</li>
     *   <li>The parent is an immediate ascendant of child.</li>
     *   <li>
     *     The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     *     relation resulted after deleting the relationship parent &lt;&lt;-- child.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteOrgInheritance( FortRequest request );


    //------------ DelegatedReviewtMgr ------------------------------------------------------------------------------------
    /**
     * Method reads Admin Role entity from the admin role container in directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.AdminRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name of the AdminRole 
     *             being targeted for read
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.AdminRole}
     */
    FortResponse readAdminRole( FortRequest request );

    
    /**
     * Method will return a list of type AdminRole matching all or part of 
     * {@link org.apache.directory.fortress.core.model.AdminRole#name}.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#value} - contains all or some of the chars corresponding to adminRole entities stored 
     *     in directory.
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.AdminRole}
     */
    FortResponse findAdminRoles( FortRequest request );

    
    /**
     * This function returns the set of adminRoles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.User} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.User} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.User#userId} - contains the userId associated with 
     *             the User object targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.UserAdminRole}
     */
    FortResponse assignedAdminRoles( FortRequest request );

    
    /**
     * This method returns the data set of all users who are assigned the given admin role.  This searches the User data set 
     * for AdminRole relationship.  This method does NOT search for hierarchical AdminRoles relationships.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.AdminRole} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.AdminRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.AdminRole#name} - contains the name to use for the 
     *             AdminRole targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.User}
     */
    FortResponse assignedAdminUsers( FortRequest request );

    
    /**
     * Commands reads existing OrgUnit entity from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.OrgUnit} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains the name associated with the 
     *             OrgUnit object targeted for search.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.OrgUnit}
     */
    FortResponse readOrg( FortRequest request );

    
    /**
     * Commands searches existing OrgUnit entities from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type parameter on API.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.OrgUnit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.OrgUnit} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#name} - contains some or all of the chars 
     *             associated with the OrgUnit objects targeted for search.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.OrgUnit#type} - contains the type of OU:  
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#USER} or 
     *             {@link org.apache.directory.fortress.core.model.OrgUnit.Type#PERM}
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *      enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type 
     * {@link org.apache.directory.fortress.core.model.OrgUnit}
     */
    FortResponse searchOrg( FortRequest request );

    
    //------------ DelegatedAccessMgr -------------------------------------------------------------------------------------
    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-assign URA.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId targeted for 
     *             operation
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for 
     *             operation.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if 
     * User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse canAssign( FortRequest request );

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-revoke URA.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the userId targeted for
     *             operation
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the Role name targeted for 
     *             operation.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User 
     * authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse canDeassign( FortRequest request );

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-assign-p PRA.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RolePerm} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.RolePerm} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#perm#objectName} - contains the permission 
     *             object name targeted for operation
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#perm#opName} - contains the permission operation 
     *             name targeted
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#role#name} - contains the Role name targeted for 
     *             operation.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User 
     * authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse canGrant( FortRequest request );

    
    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-revoke-p PRA.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.RolePerm} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.RolePerm} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#perm#objectName} - contains the permission 
     *             object name targeted for operation
     *           </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#perm#opName} - contains the permission operation 
     *             name targeted
     *            </li>
     *           <li>
     *             {@code org.apache.directory.fortress.core.model.RolePerm#role#name} - contains the Role name targeted 
     *             for operation.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User 
     * authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse canRevoke( FortRequest request );

    
    /**
     * This function returns a Boolean value meaning whether the subject of a given session is
     * allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to admin 
     *     {@link org.apache.directory.fortress.core.model.Permission} entity
     *   </li>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Permission} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#objName} - contains the name of existing 
     *             admin object being targeted
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Permission#opName} - contains the name of existing admin 
     *             permission operation
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User 
     * authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse checkAdminAccess( FortRequest request );

    
    /**
     * This function adds an AdminRole as an active role of a session whose owner is a given user.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAdminRole} 
     *     entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAdminRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole} - contains the AdminRole name targeted for 
     *             activation into User's session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     *   <li>the user is a member of the USERS data set</li>
     *   <li>the AdminRole is a member of the ADMINROLES data set</li>
     *   <li>the session is a valid Fortress session</li>
     *   <li>the user is authorized to that AdminRole</li>
     *   <li>the session is owned by that user.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    FortResponse addActiveAdminRole( FortRequest request );

    
    /**
     * This function deletes an AdminRole from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the AdminRole is an active role of that session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to 
     *     {@link org.apache.directory.fortress.core.model.UserAdminRole} entity.
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserRole} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAdminRole#name} - contains the AdminRole name 
     *             targeted for removal from User's session
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    FortResponse dropActiveAdminRole( FortRequest request );

    
    /**
     * This function returns the active admin roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type 
     * {@link org.apache.directory.fortress.core.model.UserAdminRole}.  Updated {@link FortResponse#session} will 
     * be included in response as well.
     */
    FortResponse sessionAdminRoles( FortRequest request );

    
    /**
     * This function returns the ARBAC (administrative) permissions of the session, i.e., the admin permissions assigned
     * to its authorized admin roles. The function is valid if and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type 
     * {@link org.apache.directory.fortress.core.model.Permission}.  Updated {@link FortResponse#session} will 
     * be included in response as well.
     */
    FortResponse sessionAdminPermissions( FortRequest request );

    
    /**
     * This function returns the authorized ARBAC (administrative) roles associated with a session based on hierarchical 
     * relationships. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling 
     *     {@link FortressServiceImpl#createSession} method before use in this service.
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String 
     * containing role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    FortResponse authorizedSessionAdminRoles( FortRequest request );


    //------------ PswdPolicyMgr ------------------------------------------------------------------------------------------
    /**
     * This method will add a new policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is not already present in the POLICIES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy 
     *             object class being added.
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#minAge} - This attribute holds the number of 
     *             seconds that must elapse between modifications to the password.  If this attribute is not present, 0
     *             seconds is assumed.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#maxAge} - This attribute holds the number of 
     *             seconds after which a modified password will expire. If this attribute is not present, or if the value 
     *             is 0 the password does not expire.  If not 0, the value must be greater than or equal to the value of the 
     *             pwdMinAge.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#inHistory} - This attribute specifies the maximum 
     *             number of used passwords stored in the pwdHistory attribute. If this attribute is not present, or if the 
     *             value is 0, used passwords are not stored in the pwdHistory attribute and thus may be reused.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#minLength} - When quality checking is enabled, 
     *             this attribute holds the minimum number of characters that must be used in a password.  If this attribute 
     *             is not present, no minimum password length will be enforced.  If the server is unable to check the length 
     *             (due to a hashed password or otherwise), the server will, depending on the value of the pwdCheckQuality 
     *             attribute, either accept the password without checking it ('0' or '1') or refuse it ('2').
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#expireWarning} - This attribute specifies the 
     *             maximum number of seconds before a password is due to expire that expiration warning messages will be
     *             returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     *             will be returned.  If not 0, the value must be smaller than the value of the pwdMaxAge attribute.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#graceLoginLimit} - This attribute specifies the 
     *             number of times an expired password can be used to authenticate.  If this attribute is not present or if 
     *             the value is 0, authentication will fail.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#lockout} - This attribute indicates, when its 
     *             value is "TRUE", that the password may not be used to authenticate after a specified number of
     *             consecutive failed bind attempts.  The maximum number of consecutive failed bind attempts is specified 
     *             in pwdMaxFailure.  If this attribute is not present, or if the value is "FALSE", the password may be used 
     *             to authenticate when the number of failed bind attempts has been reached.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#lockoutDuration} - This attribute holds the 
     *             number of seconds that the password cannot be used to authenticate due to too many failed bind attempts.  
     *             If this attribute is not present, or if the value is 0 the password cannot be used to authenticate until 
     *             reset by a password administrator.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#maxFailure} - This attribute specifies the number 
     *             of consecutive failed bind attempts after which the password may not be used to authenticate.<br>
     *             If this attribute is not present, or if the value is 0, this policy is not checked, and the value of 
     *             pwdLockout will be ignored.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#failureCountInterval} - This attribute holds the 
     *             number of seconds after which the password failures are purged from the failure counter, even though no
     *             successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     *             counter is only reset by a successful authentication.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#mustChange} - This attribute specifies with a 
     *             value of "TRUE" that users must change their passwords when they first bind to the directory after a
     *             password is set or reset by a password administrator.  If this attribute is not present, or if the value 
     *             is "FALSE", users are not required to change their password upon binding after the password
     *             administrator sets or resets the password.  This attribute is not set due to any actions specified by 
     *             this document, it is typically set by a password administrator after resetting a user's password.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#allowUserChange} - This attribute indicates 
     *             whether users can change their own passwords, although the change operation is still subject to access
     *             control.  If this attribute is not present, a value of "TRUE" is assumed.  This attribute is intended 
     *             to be used in the absence of an access control mechanism.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#safeModify} - This attribute specifies whether 
     *             or not the existing password must be sent along with the new password when being changed.  If this
     *             attribute is not present, a "FALSE" value is assumed.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#checkQuality} - This attribute indicates how 
     *             the password quality will be verified while being modified or added.  If this attribute is not present, 
     *             or if the value is '0', quality checking will not be enforced.  A value of '1' indicates that the server 
     *             will check the quality, and if the server is unable to check it (due to a hashed password or other
     *             reasons) it will be accepted.  A value of '2' indicates that the server will check the quality, and if 
     *             the server is unable to verify it, it will return an error refusing the password.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#attribute} - This holds the name of the attribute 
     *             to which the password policy is applied.  For example, the password policy may be applied to the
     *             userPassword attribute 
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addPolicy( FortRequest request );

    
    /**
     * This method will update an exiting policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy 
     *             object class being updated.
     *           </li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#minAge} - This attribute holds the number of 
     *             seconds that must elapse between modifications to the password.  If this attribute is not present, 0
     *             seconds is assumed.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#maxAge} - This attribute holds the number of 
     *             seconds after which a modified password will expire. If this attribute is not present, or if the value 
     *             is 0 the password does not expire.  If not 0, the value must be greater than or equal to the value of the 
     *             pwdMinAge.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#inHistory} - This attribute specifies the 
     *             maximum number of used passwords stored in the pwdHistory attribute. If this attribute is not present, or 
     *             if the value is 0, used passwords are not stored in the pwdHistory attribute and thus may be reused.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#minLength} - When quality checking is enabled, 
     *             this attribute holds the minimum number of characters that must be used in a password. If this attribute 
     *             is not present, no minimum password length will be enforced. If the server is unable to check the length 
     *             (due to a hashed password or otherwise), the server will, depending on the value of the pwdCheckQuality 
     *             attribute, either accept the password without checking it ('0' or '1') or refuse it ('2').
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#expireWarning} - This attribute specifies the 
     *             maximum number of seconds before a password is due to expire that expiration warning messages will be
     *             returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     *             will be returned.  If not 0, the value must be smaller than the value of the pwdMaxAge attribute.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#graceLoginLimit} - This attribute specifies 
     *             the number of times an expired password can be used to authenticate.  If this attribute is not present 
     *             or if the value is 0, authentication will fail.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#lockout} - This attribute indicates, when its 
     *             value is "TRUE", that the password may not be used to authenticate after a specified number of
     *             consecutive failed bind attempts.  The maximum number of consecutive failed bind attempts is specified 
     *             in pwdMaxFailure.  If this attribute is not present, or if the value is "FALSE", the password may be 
     *             used to authenticate when the number of failed bind attempts has been reached.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#lockoutDuration} - This attribute holds the 
     *             number of seconds that the password cannot be used to authenticate due to too many failed bind attempts.  
     *             If this attribute is not present, or if the value is 0 the password cannot be used to authenticate until 
     *             reset by a password administrator.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#maxFailure} - This attribute specifies the number 
     *             of consecutive failed bind attempts after which the password may not be used to authenticate.
     *             If this attribute is not present, or if the value is 0, this policy is not checked, and the value of 
     *             pwdLockout will be ignored.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#failureCountInterval} - This attribute holds the 
     *             number of seconds after which the password failures are purged from the failure counter, even though no
     *             successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     *             counter is only reset by a successful authentication.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#mustChange} - This attribute specifies with a 
     *             value of "TRUE" that users must change their passwords when they first bind to the directory after a
     *             password is set or reset by a password administrator.  If this  attribute is not present, or if the value
     *             is "FALSE", users are not required to change their password upon binding after the password administrator 
     *             sets or resets the password.  This attribute is not set due to any actions specified by this document, it 
     *             is typically set by a password administrator after resetting a user's password.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#allowUserChange} - This attribute indicates 
     *             whether users can change their own passwords, although the change operation is still subject to access
     *             control.  If this attribute is not present, a value of "TRUE" is assumed.  This attribute is intended to 
     *             be used in the absence of an access control mechanism.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#safeModify} - This attribute specifies whether 
     *             or not the existing password must be sent along with the new password when being changed. If this
     *             attribute is not present, a "FALSE" value is assumed.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#checkQuality} - This attribute indicates how 
     *             the password quality will be verified while being modified or added.  If this attribute is not present, 
     *             or if the value is '0', quality checking will not be enforced.  A value of '1' indicates that the server 
     *             will check the quality, and if the server is unable to check it (due to a hashed password or other
     *             reasons) it will be accepted.  A value of '2' indicates that the server will check the quality, and if 
     *             the server is unable to verify it, it will return an error refusing the password.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#attribute} - This holds the name of the attribute
     *             to which the password policy is applied.  For example, the password policy may be applied to the
     *             userPassword attribute 
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updatePolicy( FortRequest request );

    
    /**
     * This method will delete exiting policy entry from the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.  Existing users that
     * are assigned this policy will be removed from association.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy 
     *             object class being removed.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deletePolicy( FortRequest request );

    
    /**
     * This method will return the password policy entity to the caller.  This command is valid
     * if and only if the policy entry is present in the POLICIES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - contains the name of existing object 
     *             being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to 
     * {@link org.apache.directory.fortress.core.model.PwPolicy}
     */
    FortResponse readPolicy( FortRequest request );

    
    /**
     * This method will return a list of all password policy entities that match a particular search string.
     * This command will return an empty list of no matching entries are found.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - contains the name of existing object
     *             being targeted
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.PwPolicy}
     */
    FortResponse searchPolicy( FortRequest request );

    
    /**
     * This method will associate a user entity with a password policy entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policyName refers to a
     * policy that is a member of the PWPOLICIES data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the userId targeted for update</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.PwPolicy} 
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.PwPolicy} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.PwPolicy#name} - Maps to name attribute of pwdPolicy 
     *             object class targeted for assignment.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateUserPolicy( FortRequest request );

    
    /**
     * This method will remove the pw policy assignment from a user entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policy attribute is assigned.
     * Removal of pw policy assignment will revert the user's policy to use the global default for OpenLDAP
     * instance that contains user.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the userId targeted for removal of policy assignment</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service 
     *     will enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteUserPolicy( FortRequest request );

    
    //------------ AuditMg ------------------------------------------------------------------------------------------------
    /**
     * This method returns a list of authentication audit events for a particular user 
     * {@link org.apache.directory.fortress.core.model.UserAudit#userId}, and given timestamp field 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to 
     *             begin search
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only 
     *             failed authorization events
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.Bind}
     */
    FortResponse searchBinds( FortRequest request );
    

    /**
     * This method returns a list of authorization events for a particular user 
     * {@link org.apache.directory.fortress.core.model.UserAudit#userId} and given timestamp field 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * Method also can discriminate between all events or failed only by setting 
     * {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly}.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to 
     *             begin search
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only 
     *             failed authorization events
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    FortResponse getUserAuthZs( FortRequest request );
    

    /**
     * This method returns a list of authorization events for a particular user 
     * {@link org.apache.directory.fortress.core.model.UserAudit#userId}, object 
     * {@link org.apache.directory.fortress.core.model.UserAudit#objName}, and given timestamp field 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.<BR>
     * Method also can discriminate between all events or failed only by setting flag 
     * {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly}..
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#objName} - contains the object (authorization 
     *             resource) name
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    FortResponse searchAuthZs( FortRequest request );
    

    /**
     * This method returns a list of sessions created for a given user 
     * {@link org.apache.directory.fortress.core.model.UserAudit#userId}, and timestamp 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     *         </ul>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to 
     *             begin search
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.Mod}
     */
    FortResponse searchUserSessions( FortRequest request );
    

    /**
     * This method returns a list of admin operations events for a particular entity 
     * {@link org.apache.directory.fortress.core.model.UserAudit#dn}, object 
     * {@link org.apache.directory.fortress.core.model.UserAudit#objName} and timestamp 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.  If the internal
     * userId {@link org.apache.directory.fortress.core.model.UserAudit#internalUserId} is set it will limit search by that 
     * field.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#dn} - contains the LDAP distinguished name for 
     *             the updated object.  For example if caller wants to find out what changes were made to John Doe's user 
     *             object this would be 'uid=jdoe,ou=People,dc=example,dc=com'
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#objName} - contains the object (authorization 
     *             resource) name corresponding to the event.  For example if caller wants to return events where User object 
     *             was modified, this would be 'updateUser'
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#internalUserId} - maps to the internalUserId 
     *             of user who changed the record in LDAP. This maps to 
     *             {@link org.apache.directory.fortress.core.model.User#internalId}.
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to 
     *             begin search
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#endDate} - contains the date in which to end 
     *             search
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.Mod}
     */
    FortResponse searchAdminMods( FortRequest request );
    

    /**
     * This method returns a list of failed authentication attempts on behalf of an invalid identity 
     * {@link org.apache.directory.fortress.core.model.UserAudit#userId}, and given timestamp 
     * {@link org.apache.directory.fortress.core.model.UserAudit#beginDate}.  If the 
     * {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} is true it will return only authentication 
     * attempts made with invalid userId.  This event represents either User incorrectly entering userId during signon or
     * possible fraudulent logon attempt by hostile agent.
     * <p>
     * This event is generated when Fortress looks up User record prior to LDAP bind operation.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserAudit} 
     *     entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.UserAudit} optional parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.UserAudit#userId} - contains the target userId</li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#beginDate} - contains the date in which to 
     *             begin search
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserAudit#failedOnly} - if set to 'true', return only 
     *             failed authorization events
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.AuthZ}
     */
    FortResponse searchInvalidUsers( FortRequest request );


    //------------ ConfigMgr ----------------------------------------------------------------------------------------------
    /**
     * Create a new configuration node with given name and properties.  The name is required.  If node already exists,
     * a {@link org.apache.directory.fortress.core.SecurityException} with error 
     * {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_ALREADY_EXISTS} will be thrown.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props} 
     *     object
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addConfig( FortRequest request );
    

    /**
     * Update existing configuration node with additional properties, or, replace existing properties.  The name is 
     * required.  If node does not exist, a {@link org.apache.directory.fortress.core.SecurityException} with error 
     * {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for update</li>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props} 
     *     object
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateConfig( FortRequest request );
    

    /**
     * This service will either completely remove named configuration node from the directory or specified 
     * properties depending on the arguments passed in.
     * <p style="font-size:1.5em; color:red;">
     * If properties are not passed in along with the name, this method will remove the configuration node completely from 
     * directory.<br>
     * Care should be taken during execution to ensure target name is correct and permanent removal of all parameters located
     * there is intended.  There is no 'undo' for this operation.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for removal</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Props}
     *      object. If this argument is passed service will remove only the properties listed
     *    </li>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will enforce 
     *       ARBAC constraints
     *     </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteConfig( FortRequest request );

    
    /**
     * Read an existing configuration node with given name and return to caller.  The name is required.  If node doesn't 
     * exist, a {@link org.apache.directory.fortress.core.SecurityException} with error 
     * {@link org.apache.directory.fortress.core.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will 
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type 
     * {@link org.apache.directory.fortress.core.model.Props}
     */
    FortResponse readConfig( FortRequest request );


    //----------------------- GroupMgr -----------------------------------------

    /**
     * This command creates a new group. The command is valid only if the new group is
     * not already a member of the GROUPS data set. The GROUP data set is updated. The new group
     * does not own any session at the time of its creation.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Group}
     *     object
     *   </li>
     * </ul>
     *
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *        <h5>Group required parameters</h5>
     *       </li>
     *       <li>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.Group#name} - group name </li>
     *           <li>{@link org.apache.directory.fortress.core.model.Group#type} - either ROLE or USER group </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Group#protocol} - protocol
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Group#members} - multi-occurring contains the dn(s)
     *             of Group members, either Roles or Users
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Group optional parameters</h5>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h3>optional parameters</h3>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addGroup( FortRequest request );

    /**
     * Method returns matching Group entity that is contained within the GROUPS container in the directory.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Group} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Group} required parameters</h5>
     *         <ul>
     *           <li>
     *            {@link org.apache.directory.fortress.core.model.User#name} - contains the name associated with the
     *            Group object targeted for read.
     *          </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to
     * {@link org.apache.directory.fortress.core.model.Group}
     */
    FortResponse readGroup( FortRequest request );


    /**
     * This command deletes an existing Group from the database. The command is valid
     * if and only if the Group to be deleted is a member of the GROUPS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Group}
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>User required parameters</h5>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.Group#name} - name of the Group
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deleteGroup( FortRequest request );

    /**
     * This command update an existing Group.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Group}
     *     object
     *   </li>
     * </ul>
     *
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *        <h5>Group required parameters</h5>
     *       </li>
     *       <li>
     *         <ul>
     *           <li>{@link org.apache.directory.fortress.core.model.Group#name} - group name </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>Group optional parameters</h5>
     *       </li>
     *       <li>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Group#members} - multi-occurring contains the dn(s)
     *             of Group members, either Roles or Users
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.Group#type} - either ROLE or USER group </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Group#protocol} - protocol
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h3>optional parameters</h3>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updateGroup( FortRequest request );

    /**
     * This method returns the data set of all groups who are assigned the given role.  This searches the Groups data set
     * for Role relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *  <li>
     *    {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Role} entity
     *  </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Role} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Role#name} - contains the name to use for the Role
     *             targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type
     * {@link org.apache.directory.fortress.core.model.Group}
     */
    FortResponse assignedGroups( FortRequest request );

    /**
     * This function returns the set of roles assigned to a given group. The function is valid if and
     * only if the group is a member of the USERS data set.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.Group} entity
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>{@link org.apache.directory.fortress.core.model.Group} required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.Group#name} - contains the name associated with
     *             the Group object targeted for search.
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#session} - contains a reference to administrative session and if included service will
     *     enforce ARBAC constraints
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of
     * type {@link org.apache.directory.fortress.core.model.UserRole}
     */
    FortResponse assignedGroupRoles( FortRequest request );

    /**
     * This command assigns a group to a role.
     * <ul>
     *   <li> The command is valid if and only if:
     *   <li> The group is a member of the GROUPS data set
     *   <li> The role is a member of the ROLES data set
     *   <li> The group is not already assigned to the role
     * </ul>
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole}
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing
     *             Role to be assigned
     *           </li>
     *           <li>{@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the group name for
     *           existing Group</li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse assignGroup(FortRequest request);

    /**
     * This command deletes the assignment of the User from the Role entities. The command is
     * valid if and only if the group is a member of the GROUPS data set, the role is a member of
     * the ROLES data set, the group is assigned to the role and group have at least one role assigned.
     * Any sessions that currently have this role activated will not be effected.
     * Successful completion includes:
     * Group entity in GROUP data set has role assignment removed.
     * <h3></h3>
     * <h4>required parameters</h4>
     * <ul>
     *   <li>
     *     {@link FortRequest#entity} - contains a reference to {@link org.apache.directory.fortress.core.model.UserRole}
     *     object
     *   </li>
     * </ul>
     * <ul style="list-style-type:none">
     *   <li>
     *     <ul style="list-style-type:none">
     *       <li>
     *         <h5>UserRole required parameters</h5>
     *         <ul>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#name} - contains the name for already existing
     *             Role to be deassigned
     *           </li>
     *           <li>
     *             {@link org.apache.directory.fortress.core.model.UserRole#userId} - contains the group name for existing
     *             Group
     *           </li>
     *         </ul>
     *       </li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deassignGroup(FortRequest request);

    /**
     * This method adds a roleConstraint (ftRC) to the user ldap entry. (ftRC=ROLE_NAME$type$CONSTRAINT_TYPE$CONSTRAINT_PASETNAME$CONSTRAINT_VALUE)
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addRoleConstraint( FortRequest request );

    /**
     * Thie method removes a roleConstraint (ftRC) from the user ldap entry.
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse removeRoleConstraint( FortRequest request );

    /**
     * Thie method removes a roleConstraint (ftRC) from the user ldap entry.
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse removeRoleConstraintWid( FortRequest request );

    /**
     * This method will create a new permission attribute set object with resides under the
     * {@code ou=Constraints,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The attribute set may contain 0 to many {@link org.apache.directory.fortress.core.model.PermissionAttribute}
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addPermissionAttributeSet( FortRequest request );

    /**
     * This method will delete a permission attribute set object.
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse deletePermissionAttributeSet( FortRequest request );

    /**
     * This method adds a permission attribute (ftPA) to a permission attribute set.
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse addPermissionAttributeToSet( FortRequest request );

    /**
     * This method updates a permission attribute (ftPA) on a permission attribute set.
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse updatePermissionAttributeInSet( FortRequest request );

    /**
     * This method removed a permission attribute (ftPA) from an existing permission attribute set.
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse removePermissionAttributeFromSet( FortRequest request );

    /**
     * Find all of the role constraints for the given user and permission attribute set.
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse findRoleConstraints( FortRequest request );

    /**
     * This function returns all the permission attribute set (which contain 0 to many permission attributes)
     * for a given role. The function is valid if and only if the role is a member of the ROLES data
     * set.
     *      * <h3></h3>
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse readPermAttributeSet( FortRequest request );


    /**
     * This function returns all the permission attribute set (which contain 0 to many permission attributes)
     * for a given role. The function is valid if and only if the role is a member of the ROLES data
     * set.
     *      * <h3></h3>
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse rolePermissionAttributeSets( FortRequest request );


    /**
     * If matching jax-rs service was not found, the client will be returned a response with an error generated by this method.
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    FortResponse invalid( FortRequest request );
}