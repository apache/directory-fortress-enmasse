/*
 * Copyright (c) 2009-2014, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

import us.jts.fortress.rest.FortRequest;
import us.jts.fortress.rest.FortResponse;

/**
 * Interface for EnMasse Service methods.
 *
 * @author Shawn McKinney
 */
public interface FortressService
{
    // AdminMgr

    /**
     * This command creates a new RBAC user. The command is valid only if the new user is
     * not already a member of the USERS data set. The USER data set is updated. The new user
     * does not own any session at the time of its creation.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link us.jts.fortress.rbac.User#password} - used to authenticate the User</li>
     * <li>{@link us.jts.fortress.rbac.User#ou} - contains the name of an already existing User OU node</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#pwPolicy} - contains the name of an already existing OpenLDAP password policy node</li>
     * <li>{@link us.jts.fortress.rbac.User#cn} - maps to INetOrgPerson common name attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#sn} - maps to INetOrgPerson surname attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#description} - maps to INetOrgPerson description attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#phones} * - multi-occurring attribute maps to organizationalPerson telephoneNumber  attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#mobiles} * - multi-occurring attribute maps to INetOrgPerson mobile attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#emails} * - multi-occurring attribute maps to INetOrgPerson mail attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#address} * - multi-occurring attribute maps to organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes</li>
     * <li>{@link us.jts.fortress.rbac.User#beginTime} - HHMM - determines begin hour user may activate session</li>
     * <li>{@link us.jts.fortress.rbac.User#endTime} - HHMM - determines end hour user may activate session.</li>
     * <li>{@link us.jts.fortress.rbac.User#beginDate} - YYYYMMDD - determines date when user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#endDate} - YYYYMMDD - indicates latest date user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.User#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#timeout} - number in seconds of session inactivity time allowed</li>
     * <li>{@link us.jts.fortress.rbac.User#props} * - multi-occurring attribute contains property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link us.jts.fortress.rbac.User#roles} * - multi-occurring attribute contains the name of already existing role to assign to user</li>
     * <li>{@link us.jts.fortress.rbac.User#adminRoles} * - multi-occurring attribute contains the name of already existing adminRole to assign to user</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addUser(FortRequest request);

    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * This method performs a "hard" delete.  It completely removes all data associated with this user from the directory.
     * User entity must exist in directory prior to making this call else exception will be thrown.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteUser(FortRequest request);

    /**
     * This command deletes an existing user from the RBAC database. The command is valid
     * if and only if the user to be deleted is a member of the USERS data set. The USERS and
     * UA data sets and the assigned_users function are updated.
     * Method performs a "soft" delete.  It performs the following:
     * - sets the user status to "deleted"
     * - deassigns all roles from the user
     * - locks the user's password in LDAP
     * - revokes all perms that have been granted to user entity.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse disableUser(FortRequest request);

    /**
     * This method performs an update on User entity in directory.  Prior to making this call the entity must exist in
     * directory.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#password} - used to authenticate the User</li>
     * <li>{@link us.jts.fortress.rbac.User#ou} - contains the name of an already existing User OU node</li>
     * <li>{@link us.jts.fortress.rbac.User#pwPolicy} - contains the name of an already existing OpenLDAP password policy node</li>
     * <li>{@link us.jts.fortress.rbac.User#cn} - maps to INetOrgPerson common name attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#sn} - maps to INetOrgPerson surname attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#description} - maps to INetOrgPerson description attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#phones} * - multi-occurring attribute maps to organizationalPerson telephoneNumber  attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#mobiles} * - multi-occurring attribute maps to INetOrgPerson mobile attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#emails} * - multi-occurring attribute maps to INetOrgPerson mail attribute</li>
     * <li>{@link us.jts.fortress.rbac.User#address} * - multi-occurring attribute maps to organizationalPerson postalAddress, st, l, postalCode, postOfficeBox attributes</li>
     * <li>{@link us.jts.fortress.rbac.User#beginTime} - HHMM - determines begin hour user may activate session</li>
     * <li>{@link us.jts.fortress.rbac.User#endTime} - HHMM - determines end hour user may activate session.</li>
     * <li>{@link us.jts.fortress.rbac.User#beginDate} - YYYYMMDD - determines date when user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#endDate} - YYYYMMDD - indicates latest date user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.User#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.User#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of user may sign on</li>
     * <li>{@link us.jts.fortress.rbac.User#timeout} - number in seconds of session inactivity time allowed</li>
     * <li>{@link us.jts.fortress.rbac.User#props} * - multi-occurring attribute contains property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link us.jts.fortress.rbac.User#roles} * - multi-occurring attribute contains the name of already existing role to assign to user</li>
     * <li>{@link us.jts.fortress.rbac.User#adminRoles} * - multi-occurring attribute contains the name of already existing adminRole to assign to user</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updateUser(FortRequest request);

    /**
     * Method will change user's password.  This method will evaluate user's password policies.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link us.jts.fortress.rbac.User#password} - contains the User's old password</li>
     * <li>newPassword - contains the User's new password</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse changePassword(FortRequest request);

    /**
     * Method will lock user's password which will prevent the user from authenticating with directory.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse lockUserAccount(FortRequest request);

    /**
     * Method will unlock user's password which will enable user to authenticate with directory.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse unlockUserAccount(FortRequest request);

    /**
     * Method will reset user's password which will require user to change password before successful authentication with directory.
     * This method will not evaluate password policies on the new user password as it must be changed before use.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} object</li>
     * <h5>User required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * <li>newPassword - contains the User's new password</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse resetPassword(FortRequest request);

    /**
     * This command creates a new role. The command is valid if and only if the new role is not
     * already a member of the ROLES data set. The ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} object</li>
     * <h4>Role required parameters</h4>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role to be created.</li>
     * </ul>
     * </ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#description} - maps to description attribute on organizationalRole object class</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.Role#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addRole(FortRequest request);

    /**
     * This command deletes an existing role from the RBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ROLES data set.  This command will
     * also deassign role from all users.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} object</li>
     * <h4>Role required parameters</h4>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role to be removed.</li>
     * </ul>
     * <ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteRole(FortRequest request);

    /**
     * Method will update a Role entity in the directory.  The role must exist in role container prior to this call.     *
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} object</li>
     * <h4>Role required parameters</h4>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role to be updated.</li>
     * </ul>
     * <h4>Role optional parameters</h4>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#description} - maps to description attribute on organizationalRole object class</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.Role#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.Role#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.Role#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updateRole(FortRequest request);

    /**
     * This command assigns a user to a role.
     * <p>
     * <ul>
     * <li> The command is valid if and only if:
     * <li> The user is a member of the USERS data set
     * <li> The role is a member of the ROLES data set
     * <li> The user is not already assigned to the role
     * <li> The SSD constraints are satisfied after assignment.
     * </ul>
     * </p>
     * <p>
     * Successful completion of this op, the following occurs:
     * </p>
     * <ul>
     * <li> User entity (resides in people container) has role assignment added to aux object class attached to actual user record.
     * <li> Role entity (resides in role container) has userId added as role occupant.
     * <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:
     * <ul>
     * <li> timeout - number in seconds of session inactivity time allowed.
     * <li> beginDate - YYYYMMDD - determines date when role may be activated.
     * <li> endDate - YYMMDD - indicates latest date role may be activated.
     * <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status
     * <li> endLockDate - YYMMDD - determines end of enforced inactive status.
     * <li> beginTime - HHMM - determines begin hour role may be activated in user's session.
     * <li> endTime - HHMM - determines end hour role may be activated in user's session.*
     * <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.
     * </ul>
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} object</li>
     * <h5>UserRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the name for already existing Role to be assigned</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>UserRole optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#endTime} - HHMM - determines end hour role may be activated into user's RBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse assignUser(FortRequest request);

    /**
     * This command deletes the assignment of the User from the Role entities. The command is
     * valid if and only if the user is a member of the USERS data set, the role is a member of
     * the ROLES data set, and the user is assigned to the role.
     * Any sessions that currently have this role activated will not be effected.
     * Successful completion includes:
     * User entity in USER data set has role assignment removed.
     * Role entity in ROLE data set has userId removed as role occupant.
     * (optional) Temporal constraints will be removed from user aux object if set prior to call.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} object</li>
     * <h5>UserRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the name for already existing Role to be deassigned</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#userId} - contains the userId for existing User</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deassignUser(FortRequest request);

    /**
     * This method will add permission operation to an existing permission object which resides under {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may have {@link us.jts.fortress.rbac.Role} or {@link us.jts.fortress.rbac.User} associations.  The target {@link us.jts.fortress.rbac.Permission} must not exist prior to calling.
     * A Fortress Permission instance exists in a hierarchical, one-many relationship between its parent and itself as stored in ldap tree: ({@link us.jts.fortress.rbac.PermObj}*->{@link us.jts.fortress.rbac.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted for the permission add</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of new permission operation being added</li>
     * </ul>
     * <h5>Permission optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#roles} * - multi occurring attribute contains RBAC Roles that permission operation is being granted to</li>
     * <li>{@link us.jts.fortress.rbac.Permission#users} * - multi occurring attribute contains Users that permission operation is being granted to</li>
     * <li>{@link us.jts.fortress.rbac.Permission#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link us.jts.fortress.rbac.Permission#type} - any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addPermission(FortRequest request);

    /**
     * This method will update permission operation pre-existing in target directory under {@code ou=Permissions,ou=RBAC,dc=yourHostName,dc=com} container in directory information tree.
     * The perm operation entity may also contain {@link us.jts.fortress.rbac.Role} or {@link us.jts.fortress.rbac.User} associations to add or remove using this function.
     * The perm operation must exist before making this call.  Only non-null attributes will be updated.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted for the permission update</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of new permission operation being updated</li>
     * </ul>
     * <h5>Permission optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#roles} * - multi occurring attribute contains RBAC Roles that permission operation is being granted to</li>
     * <li>{@link us.jts.fortress.rbac.Permission#users} * - multi occurring attribute contains Users that permission operation is being granted to</li>
     * <li>{@link us.jts.fortress.rbac.Permission#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * <li>{@link us.jts.fortress.rbac.Permission#type} - any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updatePermission(FortRequest request);

    /**
     * This method will remove permission operation entity from permission object. A Fortress permission is (object->operation).
     * The perm operation must exist before making this call.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} object</li>
     * <h5>Permission required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted for the permission removal</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of new permission operation being deleted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deletePermission(FortRequest request);

    /**
     * This method will add permission object to perms container in directory. The perm object must not exist before making this call.
     * A {@link us.jts.fortress.rbac.PermObj} instance exists in a hierarchical, one-many relationship between itself and children as stored in ldap tree: ({@link us.jts.fortress.rbac.PermObj}*->{@link us.jts.fortress.rbac.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#objectName} - contains the name of new object being added</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#ou} - contains the name of an existing PERMS OrgUnit this object is associated with</li>
     * </ul>
     * <h5>PermObj optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#description} - any safe text</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#type} - contains any safe text</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addPermObj(FortRequest request);

    /**
     * This method will update permission object in perms container in directory.  The perm object must exist before making this call.
     * A {@link us.jts.fortress.rbac.PermObj} instance exists in a hierarchical, one-many relationship between itself and children as stored in ldap tree: ({@link us.jts.fortress.rbac.PermObj}*->{@link us.jts.fortress.rbac.Permission}).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#objectName} - contains the name of new object being updated</li>
     * </ul>
     * <h5>PermObj optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#ou} - contains the name of an existing PERMS OrgUnit this object is associated with</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#description} - any safe text</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#type} - contains any safe text</li>
     * <li>{@link us.jts.fortress.rbac.PermObj#props} * - multi-occurring property key and values are separated with a ':'.  e.g. mykey1:myvalue1</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updatePermObj(FortRequest request);

    /**
     * This method will remove permission object to perms container in directory.  This method will also remove
     * in associated permission objects that are attached to this object.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermObj} entity</li>
     * <h5>PermObj required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#objectName} - contains the name of new object being removed</li>
     * </ul>
     * </ul>
     * <h5>optional parameters</h5>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deletePermObj(FortRequest request);

    /**
     * This command grants a role the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the role is a member of the ROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objName} - contains the object name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#opName} - contains the operation name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#roleNm} - contains the role name</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse grant(FortRequest request);

    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a role. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the role is a member of the ROLES data set, and the permission is assigned to that role.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objName} - contains the object name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#opName} - contains the operation name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#roleNm} - contains the role name</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse revoke(FortRequest request);

    /**
     * This command grants a user the permission to perform an operation on an object to a role.
     * The command is implemented by granting permission by setting the access control list of
     * the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * and the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objName} - contains the object name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#opName} - contains the operation name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse grantUser(FortRequest request);

    /**
     * This command revokes the permission to perform an operation on an object from the set
     * of permissions assigned to a user. The command is implemented by setting the access control
     * list of the object involved.
     * The command is valid if and only if the pair (operation, object) represents a permission,
     * the user is a member of the USERS data set, and the permission is assigned to that user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermGrant} entity</li>
     * <h5>PermGrant required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objName} - contains the object name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#opName} - contains the operation name</li>
     * <li>{@link us.jts.fortress.rbac.PermGrant#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>PermGrant optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermGrant#objId} - contains the object id</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse revokeUser(FortRequest request);

    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     * <li> The childRole is not a member of the ROLES data set.
     * <li> The parentRole is a member of the ROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new role.
     * <li> Assigns role relationship between new childRole and pre-existing parentRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing parent role</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of new child role</li>
     * </ul>
     * <h5>optional parameters {@link us.jts.fortress.rbac.RoleRelationship#child}</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#description} - maps to description attribute on organizationalRole object class for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addDescendant(FortRequest request);

    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole.
     * <p>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole is not a member of the ROLES data set.
     * <li> The childRole is a member of the ROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new role.
     * <li> Assigns role relationship between new parentRole and pre-existing childRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>childRole - {@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing child Role</li>
     * <li>parentRole - {@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of new Role to be parent</li>
     * </ul>
     * <h5>optional parameters {@link us.jts.fortress.rbac.RoleRelationship#parent}</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#description} - maps to description attribute on organizationalRole object class for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addAscendant(FortRequest request);

    /**
     * This commands establishes a new immediate inheritance relationship parentRole <<-- childRole between existing
     * roles parentRole, childRole.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole and childRole are members of the ROLES data set.
     * <li> The parentRole is not an immediate ascendant of childRole.
     * <li> The childRole does not properly inherit parentRole (in order to avoid cycle creation).
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing role to be parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing role to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addInheritance(FortRequest request);

    /**
     * This command deletes an existing immediate inheritance relationship parentRole <<-- childRole.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The roles parentRole and childRole are members of the ROLES data set.
     * <li> The parentRole is an immediate ascendant of childRole.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parentRole <<-- childRole.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing Role to remove parent relationship</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing Role to remove child relationship</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteInheritance(FortRequest request);

    /**
     * This command creates a named SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the SSD set is not already in use.
     * <li> All the roles in the SSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     * <li> The SSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of new SSD role set to be added</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse createSsdSet(FortRequest request);

    /**
     * This command updates existing SSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the SSD set exists in directory.
     * <li> All the roles in the SSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the SSD role set.
     * <li> The SSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set to be modified</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse updateSsdSet(FortRequest request);

    /**
     * This command adds a role to a named SSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The role to be added is a member of the ROLES data set but not of a member of the SSD role set.
     * <li> The SSD constraint is satisfied after the addition of the role to the SSD role set.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to add as member to SSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse addSsdRoleMember(FortRequest request);

    /**
     * This command removes a role from a named SSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The role to be removed is a member of the SSD role set.
     * <li> The cardinality associated with the SSD role set is less than the number of elements of the SSD role set.
     * </ul>
     * Note that the SSD constraint should be satisfied after the removal of the role from the SSD role set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to remove as member to SSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse deleteSsdRoleMember(FortRequest request);

    /**
     * This command deletes a SSD role set completely. The command is valid if and only if the SSD role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set targeted for removal</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse deleteSsdSet(FortRequest request);

    /**
     * This command sets the cardinality associated with a given SSD role set.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The SSD role set exists.
     * <li> The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of elements of the SSD role set.
     * <li> The SSD constraint is satisfied after setting the new cardinality.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set targeted for update</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - contains new cardinality setting for SSD</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse setSsdSetCardinality(FortRequest request);

    /**
     * This command creates a named DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the DSD set is not already in use.
     * <li> All the roles in the DSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     * <li> The DSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of new DSD role set to be added</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse createDsdSet(FortRequest request);

    /**
     * This command updates existing DSD set of roles and sets the cardinality n of its subsets
     * that cannot have common users.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li>The name of the DSD set exists in directory.
     * <li> All the roles in the DSD set are members of the ROLES data set.
     * <li> n is a natural number greater than or equal to 2 and less than or equal to the cardinality of the DSD role set.
     * <li> The DSD constraint for the new role set is satisfied.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing SSD role set to be modified</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.SDSet} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#members} * - multi-occurring attribute contains the RBAC Role names to be added to this set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - default is 2 which is one more than maximum number of Roles that may be assigned to User from a particular set</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse updateDsdSet(FortRequest request);

    /**
     * This command adds a role to a named DSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The role to be added is a member of the ROLES data set but not of a member of the DSD role set.
     * <li> The DSD constraint is satisfied after the addition of the role to the DSD role set.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to add as member to DSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse addDsdRoleMember(FortRequest request);

    /**
     * This command removes a role from a named DSD set of roles. The cardinality associated with the role set remains unchanged.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The role to be removed is a member of the DSD role set.
     * <li> The cardinality associated with the DSD role set is less than the number of elements of the DSD role set.
     * </ul>
     * Note that the DSD constraint should be satisfied after the removal of the role from the DSD role set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the Role name to remove as member to DSD set</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse deleteDsdRoleMember(FortRequest request);

    /**
     * This command deletes a DSD role set completely. The command is valid if and only if the DSD role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing DSD role set targeted for removal</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse deleteDsdSet(FortRequest request);

    /**
     * This command sets the cardinality associated with a given DSD role set.
     * <p/>
     * The command is valid if and only if:
     * <ul>
     * <li> The DSD role set exists.
     * <li> The new cardinality is a natural number greater than or equal to 2 and less than or equal to the number of elements of the DSD role set.
     * <li> The DSD constraint is satisfied after setting the new cardinality.
     * </ul>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing DSD role set targeted for update</li>
     * <li>{@link us.jts.fortress.rbac.SDSet#cardinality} - contains new cardinality setting for DSD</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.SDSet}
     */
    public FortResponse setDsdSetCardinality(FortRequest request);

    // ReviewMgr

    /**
     * This method returns a matching permission entity to caller.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.Permission}
     */
    public FortResponse readPermission(FortRequest request);

    /**
     * Method reads permission object from perm container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermObj} entity</li>
     * <h5>{@link us.jts.fortress.rbac.PermObj} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#objectName} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.PermObj}
     */
    public FortResponse readPermObj(FortRequest request);

    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains one or more characters of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains one or more characters of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.Permission}
     */
    public FortResponse findPermissions(FortRequest request);

    /**
     * Method returns a list of type Permission that match the perm object search string.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PermObj} entity</li>
     * <h5>{@link us.jts.fortress.rbac.PermObj} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PermObj#objectName} - contains one or more characters of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.PermObj}
     */
    public FortResponse findPermObjs(FortRequest request);

    /**
     * Method reads Role entity from the role container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role to read.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.Role}
     */
    public FortResponse readRole(FortRequest request);

    /**
     * Method will return a list of type Role matching all or part of {@link us.jts.fortress.rbac.Role#name}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains all or some of the chars corresponding to role entities stored in directory.</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.Role}
     */
    public FortResponse findRoles(FortRequest request);

    /**
     * Method returns matching User entity that is contained within the people container in the directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains the userId associated with the User object targeted for read.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.User}
     */
    public FortResponse readUser(FortRequest request);

    /**
     * Return a list of type User of all users in the people container that match all or part of the {@link us.jts.fortress.rbac.User#userId} or {@link us.jts.fortress.rbac.User#ou} fields passed in User entity.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains all or some leading chars that match userId(s) stored in the directory.</li>
     * <li>{@link us.jts.fortress.rbac.User#ou} - contains one or more characters of org unit associated with existing object(s) being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.User}
     */
    public FortResponse findUsers(FortRequest request);

    /**
     * This method returns the data set of all users who are assigned the given role.  This searches the User data set for
     * Role relationship.  This method does NOT search for hierarchical RBAC Roles relationships.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.User}
     */
    public FortResponse assignedUsers(FortRequest request);

    /**
     * This function returns the set of roles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.UserRole}
     */
    public FortResponse assignedRoles(FortRequest request);

    /**
     * This function returns the set of users authorized to a given role, i.e., the users that are assigned to a role that
     * inherits the given role. The function is valid if and only if the given role is a member of the ROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.User}
     */
    public FortResponse authorizedUsers(FortRequest request);

    /**
     * This function returns the set of roles authorized for a given user. The function is valid if
     * and only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing the User's authorized role names.
     */
    public FortResponse authorizedRoles(FortRequest request);

    /**
     * Return a list of type String of all roles that have granted a particular permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing role names that permission has been granted to.
     */
    public FortResponse permissionRoles(FortRequest request);

    /**
     * This function returns the set of all permissions (op, obj), granted to or inherited by a
     * given role. The function is valid if and only if the role is a member of the ROLES data
     * set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.Permission} containing permissions for role.
     */
    public FortResponse rolePermissions(FortRequest request);

    /**
     * This function returns the set of permissions a given user gets through his/her authorized
     * roles. The function is valid if and only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.Permission} containing permissions for user.
     */
    public FortResponse userPermissions(FortRequest request);

    /**
     * Return all role names that have been authorized for a given permission.  This will process role hierarchies to determine set of all Roles who have access to a given permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing role names that permission has been granted to.
     */
    public FortResponse authorizedPermissionRoles(FortRequest request);

    /**
     * Return all userIds that have been granted (directly) a particular permission.  This will not consider assigned or authorized Roles.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing userIds that permission has been granted to.
     */
    public FortResponse permissionUsers(FortRequest request);

    /**
     * Return all userIds that have been authorized for a given permission.  This will process role hierarchies to determine set of all Users who have access to a given permission.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing userIds that permission is authorized for.
     */
    public FortResponse authorizedPermissionUsers(FortRequest request);

    /**
     * This function returns the list of all SSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all SSD role sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.SDSet} containing all matching SSD sets.
     */
    public FortResponse ssdRoleSets(FortRequest request);

    /**
     * This function returns the SSD data set that matches a particular set name.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type {@link us.jts.fortress.rbac.SDSet} containing matching SSD set.
     */
    public FortResponse ssdRoleSet(FortRequest request);

    /**
     * This function returns the set of roles of a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing all member roles of SSD set.
     */
    public FortResponse ssdRoleSetRoles(FortRequest request);

    /**
     * This function returns the cardinality associated with a SSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>name contains the name of existing SSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    public FortResponse ssdRoleSetCardinality(FortRequest request);

    /**
     * This function returns the list of all SSD sets that have a particular SSD set name.
     * If the parameter is left blank, function will return all SSD sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name to use for the search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.SDSet} containing all matching SSD sets.
     */
    public FortResponse ssdSets(FortRequest request);

    /**
     * This function returns the list of all DSD role sets that have a particular Role as member or Role's
     * parent as a member.  If the Role parameter is left blank, function will return all DSD role sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Role} entity</li>
     * <h5>{@link us.jts.fortress.rbac.Role} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Role#name} - contains the name to use for the Role targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.SDSet} containing all matching DSD sets.
     */
    public FortResponse dsdRoleSets(FortRequest request);

    /**
     * This function returns the DSD data set that matches a particular set name.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to an object of type {@link us.jts.fortress.rbac.SDSet} containing matching DSD set.
     */
    public FortResponse dsdRoleSet(FortRequest request);

    /**
     * This function returns the set of roles of a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#values} contains a reference to a List of type String containing all member roles of DSD set.
     */
    public FortResponse dsdRoleSetRoles(FortRequest request);

    /**
     * This function returns the cardinality associated with a DSD role set. The function is valid if and only if the
     * role set exists.
     * <h4>required parameters</h4>
     * <ul>
     * <li>name contains the name of existing DSD set being targeted</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains the cardinality.
     */
    public FortResponse dsdRoleSetCardinality(FortRequest request);

    /**
     * This function returns the list of all DSD sets that have a particular DSD set name.
     * If the parameter is left blank, function will return all DSD sets.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.SDSet} entity</li>
     * <h5>{@link us.jts.fortress.rbac.SDSet} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.SDSet#name} - contains the name to use for the search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.SDSet} containing all matching DSD sets.
     */
    public FortResponse dsdSets(FortRequest request);

    // AccessMgr

    /**
     * Perform user authentication only.  It does not activate RBAC roles in session but will evaluate
     * password policies.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link us.jts.fortress.rbac.User#password} - used to authenticate the User</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will be returned if authentication successful.  This will not contain user's roles.
     */
    public FortResponse authenticate(FortRequest request);

    /**
     * Perform user authentication {@link us.jts.fortress.rbac.User#password} and role activations.<br />
     * This method must be called once per user prior to calling other methods within this class.
     * The successful result is {@link us.jts.fortress.rbac.Session} that contains target user's RBAC {@link us.jts.fortress.rbac.User#roles} and Admin role {@link us.jts.fortress.rbac.User#adminRoles}.<br />
     * In addition to checking user password validity it will apply configured password policy checks {@link us.jts.fortress.rbac.User#pwPolicy}..<br />
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * <li>{@link us.jts.fortress.rbac.User#password} - used to authenticate the User</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#roles} * - multi-occurring attribute contains the names of assigned RBAC roles targeted for activation into Session.</li>
     * <li>{@link us.jts.fortress.rbac.User#adminRoles} * - multi-occurring attribute contains the names of assigned ARBAC roles targeted for activation into Session.</li>
     * <li>{@link us.jts.fortress.rbac.User#props} collection of name value pairs collected on behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     * </ul>
     * </ul>
     * <h4> This API will...</h4>
     * <ul>
     * <li> authenticate user password.
     * <li> perform <a href="http://www.openldap.org/">OpenLDAP</a> <a href="http://tools.ietf.org/html/draft-behera-ldap-password-policy-10">password policy evaluation</a>.
     * <li> fail for any user who is locked by OpenLDAP's policies {@link us.jts.fortress.rbac.User#isLocked()}.
     * <li> evaluate temporal {@link us.jts.fortress.util.time.Constraint}(s) on {@link us.jts.fortress.rbac.User}, {@link us.jts.fortress.rbac.UserRole} and {@link us.jts.fortress.rbac.UserAdminRole} entities.
     * <li> process selective role activations into User RBAC Session {@link us.jts.fortress.rbac.User#roles}.
     * <li> check Dynamic Separation of Duties {@link us.jts.fortress.rbac.DSDChecker#validate(us.jts.fortress.rbac.Session, us.jts.fortress.util.time.Constraint, us.jts.fortress.util.time.Time)} on {@link us.jts.fortress.rbac.User#roles}.
     * <li> process selective administrative role activations {@link us.jts.fortress.rbac.User#adminRoles}.
     * <li> return a {@link us.jts.fortress.rbac.Session} containing {@link us.jts.fortress.rbac.Session#getUser()}, {@link us.jts.fortress.rbac.Session#getRoles()} and (if admin user) {@link us.jts.fortress.rbac.Session#getAdminRoles()} if everything checks out good.
     * <li> return a checked exception that will be {@link us.jts.fortress.SecurityException} or its derivation.
     * <li> return a {@link us.jts.fortress.SecurityException} for system failures.
     * <li> return a {@link us.jts.fortress.PasswordException} for authentication and password policy violations.
     * <li> return a {@link us.jts.fortress.ValidationException} for data validation errors.
     * <li> return a {@link us.jts.fortress.FinderException} if User id not found.
     * <li> (optionally) store parms passed in by client for audit trail purposes.
     * </ul>
     * <h4>
     * The function is valid if and only if:
     * </h4>
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the password is supplied (unless trusted).
     * <li> the (optional) active role set is a subset of the roles authorized for that user.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result code {@link us.jts.fortress.rbac.Session#errorId}, RBAC role activations {@link us.jts.fortress.rbac.Session#getRoles()}, Admin Role activations {@link us.jts.fortress.rbac.Session#getAdminRoles()},OpenLDAP pw policy codes {@link us.jts.fortress.rbac.Session#warningId}, {@link us.jts.fortress.rbac.Session#expirationSeconds}, {@link us.jts.fortress.rbac.Session#graceLogins} and more.
     */
    public FortResponse createSession(FortRequest request);

    /**
     * This service accepts userId for validation and returns RBAC session.  This service will not check the password nor perform password policy validations.<br />
     * The successful result is {@link us.jts.fortress.rbac.Session} that contains target user's RBAC {@link us.jts.fortress.rbac.User#roles} and Admin role {@link us.jts.fortress.rbac.User#adminRoles}.<br />
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - maps to INetOrgPerson uid</li>
     * </ul>
     * <h5>User optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#roles} * - multi-occurring attribute contains the names of assigned RBAC roles targeted for activation into Session.</li>
     * <li>{@link us.jts.fortress.rbac.User#adminRoles} * - multi-occurring attribute contains the names of assigned ARBAC roles targeted for activation into Session.</li>
     * <li>{@link us.jts.fortress.rbac.User#props} collection of name value pairs collected on behalf of User during signon.  For example hostname:myservername or ip:192.168.1.99
     * </ul>
     * </ul>
     * <h4> This API will...</h4>
     * <ul>
     * <li> fail for any user who is locked by OpenLDAP's policies {@link us.jts.fortress.rbac.User#isLocked()}.
     * <li> evaluate temporal {@link us.jts.fortress.util.time.Constraint}(s) on {@link us.jts.fortress.rbac.User}, {@link us.jts.fortress.rbac.UserRole} and {@link us.jts.fortress.rbac.UserAdminRole} entities.
     * <li> process selective role activations into User RBAC Session {@link us.jts.fortress.rbac.User#roles}.
     * <li> check Dynamic Separation of Duties {@link us.jts.fortress.rbac.DSDChecker#validate(us.jts.fortress.rbac.Session, us.jts.fortress.util.time.Constraint, us.jts.fortress.util.time.Time)} on {@link us.jts.fortress.rbac.User#roles}.
     * <li> process selective administrative role activations {@link us.jts.fortress.rbac.User#adminRoles}.
     * <li> return a {@link us.jts.fortress.rbac.Session} containing {@link us.jts.fortress.rbac.Session#getUser()}, {@link us.jts.fortress.rbac.Session#getRoles()} and (if admin user) {@link us.jts.fortress.rbac.Session#getAdminRoles()} if everything checks out good.
     * <li> return a checked exception that will be {@link us.jts.fortress.SecurityException} or its derivation.
     * <li> return a {@link us.jts.fortress.SecurityException} for system failures.
     * <li> return a {@link us.jts.fortress.ValidationException} for data validation errors.
     * <li> return a {@link us.jts.fortress.FinderException} if User id not found.
     * <li> (optionally) store parms passed in by client for audit trail purposes.
     * </ul>
     * <h4>
     * The function is valid if and only if:
     * </h4>
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the (optional) active role set is a subset of the roles authorized for that user.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#session} object will contain authentication result code {@link us.jts.fortress.rbac.Session#errorId}, RBAC role activations {@link us.jts.fortress.rbac.Session#getRoles()}, Admin Role activations {@link us.jts.fortress.rbac.Session#getAdminRoles()},OpenLDAP pw policy codes {@link us.jts.fortress.rbac.Session#warningId}, {@link us.jts.fortress.rbac.Session#expirationSeconds}, {@link us.jts.fortress.rbac.Session#graceLogins} and more.
     */
    public FortResponse createSessionTrusted(FortRequest request);

    /**
     * Perform user RBAC authorization.  This function returns a Boolean value meaning whether the subject of a given session is
     * allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Permission} entity</li>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing permission operation</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse checkAccess(FortRequest request);

    /**
     * This function returns the permissions of the session, i.e., the permissions assigned
     * to its authorized roles. The function is valid if and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link us.jts.fortress.rbac.Permission}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse sessionPermissions(FortRequest request);

    /**
     * This function returns the active roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link us.jts.fortress.rbac.UserRole}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse sessionRoles(FortRequest request);

    /**
     * This function returns the authorized roles associated with a session based on hierarchical relationships. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String containing role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse authorizedSessionRoles(FortRequest request);

    /**
     * This function adds a role as an active role of a session whose owner is a given user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the Role name targeted for activation into User's session</li>
     * </ul>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the role is a member of the ROLES data set
     * <li> the role inclusion does not violate Dynamic Separation of Duty Relationships
     * <li> the session is a valid Fortress session
     * <li> the user is authorized to that role
     * <li> the session is owned by that user.
     * </ul>
     * </p>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    public FortResponse addActiveRole(FortRequest request);

    /**
     * This function deletes a role from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the role is an active role of that session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the Role name targeted for removal from User's session</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    public FortResponse dropActiveRole(FortRequest request);

    /**
     * This function returns the userId value that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to {@link us.jts.fortress.rbac.User#userId} only.
     */
    public FortResponse getUserId(FortRequest request);

    /**
     * This function returns the user object that is contained within the session object.
     * The function is valid if and only if the session object contains a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains reference to {@link us.jts.fortress.rbac.User}.
     */
    public FortResponse getUser(FortRequest request);

    // DelegatedAdminMgrImpl

    /**
     * This command creates a new admin role. The command is valid if and only if the new admin role is not
     * already a member of the ADMIN ROLES data set. The ADMIN ROLES data set is updated.
     * Initially, no user or permission is assigned to the new role.
     * <p/>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.AdminRole} object</li>
     * <h5>AdminRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#name} - contains the name of the new AdminRole being targeted for addition to LDAP</li>
     * </ul>
     * <h5>AdminRole optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#description} - contains any safe text</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#osPs} * - multi-occurring attribute used to set associations to existing PERMS OrgUnits</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#osUs} * - multi-occurring attribute used to set associations to existing USERS OrgUnits</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginRange} - contains the name of an existing RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole activated) controls</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endRange} - contains the name of an existing RBAC Role that represents that highest role in hierarchy that administrator may control</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginInclusive} - if 'true' the RBAC Role specified in beginRange is also controlled by the posessor of this AdminRole</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endInclusive} - if 'true' the RBAC Role specified in endRange is also controlled by the administratrator</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginTime} - HHMM - determines begin hour adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endTime} - HHMM - determines end hour adminRole may be activated into user's ARBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginDate} - YYYYMMDD - determines date when adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endDate} - YYYYMMDD - indicates latest date adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     * </ul>
     * </ul>
     * <p/>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link us.jts.fortress.rbac.AdminRole}.
     */
    public FortResponse addAdminRole(FortRequest request);

    /**
     * This command deletes an existing admin role from the ARBAC database. The command is valid
     * if and only if the role to be deleted is a member of the ADMIN ROLES data set.  This command will
     * also deassign role from all users.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.AdminRole} object</li>
     * <h5>AdminRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#name} - contains the name of the new AdminRole being targeted for removal from LDAP</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link us.jts.fortress.rbac.AdminRole}.
     */
    public FortResponse deleteAdminRole(FortRequest request);

    /**
     * Method will update an AdminRole entity in the directory.  The role must exist in directory prior to this call.     *
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.AdminRole} object</li>
     * <h5>AdminRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#name} - contains the name of the new AdminRole being targeted for update to LDAP</li>
     * </ul>
     * <h5>AdminRole optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#description} - contains any safe text</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#osPs} * - multi-occurring attribute used to set associations to existing PERMS OrgUnits</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#osUs} * - multi-occurring attribute used to set associations to existing USERS OrgUnits</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginRange} - contains the name of an existing RBAC Role that represents the lowest role in hierarchy that administrator (whoever has this AdminRole activated) controls</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endRange} - contains the name of an existing RBAC Role that represents that highest role in hierarchy that administrator may control</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginInclusive} - if 'true' the RBAC Role specified in beginRange is also controlled by the posessor of this AdminRole</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endInclusive} - if 'true' the RBAC Role specified in endRange is also controlled by the administratrator</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginTime} - HHMM - determines begin hour adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endTime} - HHMM - determines end hour adminRole may be activated into user's ARBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginDate} - YYYYMMDD - determines date when adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endDate} - YYYYMMDD - indicates latest date adminRole may be activated into user's ARBAC session</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.AdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to a {@link us.jts.fortress.rbac.AdminRole}.
     */
    public FortResponse updateAdminRole(FortRequest request);

    /**
     * This command assigns a user to an administrative role.
     * <p>
     * <ul>
     * <li> The command is valid if and only if:
     * <li> The user is a member of the USERS data set
     * <li> The role is a member of the ADMIN ROLES data set
     * <li> The user is not already assigned to the admin role
     * </ul>
     * </p>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAdminRole} object</li>
     * <h5>UserAdminRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#name} - contains the name for already existing AdminRole to be assigned</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#userId} - contains the userId for existing User</li>
     * </ul>
     * <h5>UserAdminRole optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#beginTime} - HHMM - determines begin hour AdminRole may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#endTime} - HHMM - determines end hour AdminRole may be activated into user's RBAC session.</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#beginDate} - YYYYMMDD - determines date when AdminRole may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#endDate} - YYYYMMDD - indicates latest date AdminRole may be activated into user's RBAC session</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#endLockDate} - YYYYMMDD - determines end of enforced inactive status</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's ARBAC session</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * <p>
     * Successful completion of this op, the following occurs:
     * </p>
     * <ul>
     * <li> User entity (resides in people container) has role assignment added to aux object class attached to actual user record.
     * <li> AdminRole entity (resides in adminRole container) has userId added as role occupant.
     * <li> (optional) Temporal constraints may be associated with <code>ftUserAttrs</code> aux object class based on:
     * <ul>
     * <li> timeout - number in seconds of session inactivity time allowed.
     * <li> beginDate - YYYYMMDD - determines date when role may be activated.
     * <li> endDate - YYMMDD - indicates latest date role may be activated.
     * <li> beginLockDate - YYYYMMDD - determines beginning of enforced inactive status
     * <li> endLockDate - YYMMDD - determines end of enforced inactive status.
     * <li> beginTime - HHMM - determines begin hour role may be activated in user's session.
     * <li> endTime - HHMM - determines end hour role may be activated in user's session.*
     * <li> dayMask - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day of week role may be activated.
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse assignAdminUser(FortRequest request);

    /**
     * This method removes assigned admin role from user entity.  Both user and admin role entities must exist and have role relationship
     * before calling this method.
     * Successful completion:
     * del Role to User assignment in User data set
     * AND
     * User to Role assignment in Admin Role data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAdminRole} object</li>
     * <h5>UserAdminRole required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#name} - contains the name for already existing AdminRole to be deassigned</li>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#userId} - contains the userId for existing User</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deassignAdminUser(FortRequest request);

    /**
     * This commands creates a new role childRole, and inserts it in the role hierarchy as an immediate descendant of
     * the existing role parentRole. The command is valid if and only if childRole is not a member of the ADMINROLES data set,
     * and parentRole is a member of the ADMINROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing parent role</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of new child role</li>
     * </ul>
     * <h5>optional parameters {@code us.jts.fortress.rbac.RoleRelationship#child}</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#description} - maps to description attribute on organizationalRole object class for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new child</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The childRole is not a member of the ADMINROLES data set.
     * <li> The parentRole is a member of the ADMINROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new adminRole.
     * <li> Assigns role relationship between new childRole and pre-existing parentRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addAdminDescendant(FortRequest request);

    /**
     * This commands creates a new role parentRole, and inserts it in the role hierarchy as an immediate ascendant of
     * the existing role childRole. The command is valid if and only if parentRole is not a member of the ADMINROLES data set,
     * and childRole is a member of the ADMINROLES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>childRole - {@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing child AdminRole</li>
     * <li>parentRole - {@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of new AdminRole to be parent</li>
     * </ul>
     * <h5>optional parameters {@link us.jts.fortress.rbac.RoleRelationship#parent}</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#description} - maps to description attribute on organizationalRole object class for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginTime} - HHMM - determines begin hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endTime} - HHMM - determines end hour role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginDate} - YYYYMMDD - determines date when role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endDate} - YYYYMMDD - indicates latest date role may be activated into user's RBAC session for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#beginLockDate} - YYYYMMDD - determines beginning of enforced inactive status for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#endLockDate} - YYYYMMDD - determines end of enforced inactive status for new parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#dayMask} - 1234567, 1 = Sunday, 2 = Monday, etc - specifies which day role may be activated into user's RBAC session for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole is not a member of the ADMINROLES data set.
     * <li> The childRole is a member of the ADMINROLES data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new adminRole.
     * <li> Assigns role relationship between new parentRole and pre-existing childRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addAdminAscendant(FortRequest request);

    /**
     * This commands establishes a new immediate inheritance relationship parentRole <<-- childRole between existing
     * roles parentRole, childRole. The command is valid if and only if parentRole and childRole are members of the ADMINROLES data
     * set, parentRole is not an immediate ascendant of childRole, and childRole does not properly inherit parentRole (in order to
     * avoid cycle creation).
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing AdminRole to be parent</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing AdminRole to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parentRole and childRole are members of the ADMINROLES data set.
     * <li> The parentRole is not an immediate ascendant of childRole.
     * <li> The childRole does not properly inherit parentRole (in order to avoid cycle creation).
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addAdminInheritance(FortRequest request);

    /**
     * This command deletes an existing immediate inheritance relationship parentRole <<-- childRole. The command is
     * valid if and only if the adminRoles parentRole and childRole are members of the ADMINROLES data set, and parentRole is an
     * immediate ascendant of childRole. The new inheritance relation is computed as the reflexive-transitive
     * closure of the immediate inheritance relation resulted after deleting the relationship parentRole <<-- childRole.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RoleRelationship} entity</li>
     * <h5>RoleRelationship required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#parent#name} - contains the name of existing Role to remove parent relationship</li>
     * <li>{@code us.jts.fortress.rbac.RoleRelationship#child#name} - contains the name of existing Role to remove child relationship</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The roles parentRole and childRole are members of the ADMINROLES data set.
     * <li> The parentRole is an immediate ascendant of childRole.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parentRole <<-- childRole.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteAdminInheritance(FortRequest request);

    /**
     * Commands adds a new OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#name} - contains the name of new USERS or PERMS OrgUnit to be added</li>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#type} - contains the type of OU:  {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * </ul>
     * <h5>OrgUnit optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addOrg(FortRequest request);

    /**
     * Commands updates existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#name} - contains the name of USERS or PERMS OrgUnit to be updated</li>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#type} - contains the type of OU:  {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * </ul>
     * <h5>OrgUnit optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#description} - contains any safe text</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updateOrg(FortRequest request);

    /**
     * Commands deletes existing OrgUnit entity to OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnit} object</li>
     * <h5>OrgUnit required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#name} - contains the name of USERS or PERMS OrgUnit to be removed</li>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#type} - contains the type of OU:  {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteOrg(FortRequest request);

    /**
     * This commands creates a new orgunit child, and inserts it in the orgunit hierarchy as an immediate descendant of
     * the existing orgunit parent.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to be parent</li>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to be child</li>
     * </ul>
     * <h5>optional parameters {@code us.jts.fortress.rbac.RoleRelationship#child}</h5>
     * <ul>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#description} - maps to description attribute on organizationalUnit object class for new child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The child orgunit is not a member of the ORGUNITS data set.
     * <li> The parent orgunit is a member of the ORGUNITS data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new orgunit.
     * <li> Assigns orgunit relationship between new child and pre-existing parent.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addOrgDescendant(FortRequest request);

    /**
     * This commands creates a new orgunit parent, and inserts it in the orgunit hierarchy as an immediate ascendant of
     * the existing child orgunit.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#name} - contains the name of existing OrgUnit to be child</li>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#type} - contains the type of OrgUnit targeted: {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#name} - contains the name of new OrgUnit to be parent</li>
     * </ul>
     * <h5>optional parameters {@link us.jts.fortress.rbac.RoleRelationship#parent}</h5>
     * <ul>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#description} - maps to description attribute on organizationalUnit object class for new parent</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parent is not a member of the ORGUNITS data set.
     * <li> The child is a member of the ORGUNITS data set.
     * </ul>
     * </p>
     * <p> This method:
     * <ul>
     * <li> Adds new orgunit.
     * <li> Assigns orgunit relationship between new parent and pre-existing child.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addOrgAscendant(FortRequest request);

    /**
     * This commands establishes a new immediate inheritance relationship with parent orgunit <<-- child orgunit
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to be parent</li>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to be child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The parent and child are members of the ORGUNITS data set.
     * <li> The parent is not an immediate ascendant of child.
     * <li> The child does not properly inherit parent (in order to avoid cycle creation).
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addOrgInheritance(FortRequest request);

    /**
     * This command deletes an existing immediate inheritance relationship parent <<-- child.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnitRelationship} entity</li>
     * <h5>OrgUnitRelationship required parameters</h5>
     * <ul>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#name} - contains the name of existing OrgUnit to remove as parent</li>
     * <li>parent - {@code us.jts.fortress.rbac.OrgUnitRelationship#parent#type} - contains the type of OrgUnit targeted: {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * <li>child - {@code us.jts.fortress.rbac.OrgUnitRelationship#child#name} - contains the name of new OrgUnit to remove as child</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     * The command is valid if and only if:
     * <ul>
     * <li> The orgunits parent and child are members of the ORGUNITS data set.
     * <li> The parent is an immediate ascendant of child.
     * <li> The new inheritance relation is computed as the reflexive-transitive closure of the immediate inheritance
     * relation resulted after deleting the relationship parent <<-- child.
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteOrgInheritance(FortRequest request);

    // DelegatedReviewMgr

    /**
     * Method reads Admin Role entity from the admin role container in directory.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.AdminRole} entity</li>
     * <h5>{@link us.jts.fortress.rbac.AdminRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#name} - contains the name of the AdminRole being targeted for read</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.AdminRole}
     */
    public FortResponse readAdminRole(FortRequest request);

    /**
     * Method will return a list of type AdminRole matching all or part of {@link us.jts.fortress.rbac.AdminRole#name}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains all or some of the chars corresponding to adminRole entities stored in directory.</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.AdminRole}
     */
    public FortResponse findAdminRoles(FortRequest request);

    /**
     * This function returns the set of adminRoles assigned to a given user. The function is valid if and
     * only if the user is a member of the USERS data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.User} entity</li>
     * <h5>{@link us.jts.fortress.rbac.User} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.User#userId} - contains the userId associated with the User object targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.UserAdminRole}
     */
    public FortResponse assignedAdminRoles(FortRequest request);

    /**
     * This method returns the data set of all users who are assigned the given admin role.  This searches the User data set for
     * AdminRole relationship.  This method does NOT search for hierarchical AdminRoles relationships.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.AdminRole} entity</li>
     * <h5>{@link us.jts.fortress.rbac.AdminRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.AdminRole#name} - contains the name to use for the AdminRole targeted for search.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.User}
     */
    public FortResponse assignedAdminUsers(FortRequest request);

    /**
     * Commands reads existing OrgUnit entity from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type attribute.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.OrgUnit} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#name} - contains the name associated with the OrgUnit object targeted for search.</li>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#type} - contains the type of OU:  {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.OrgUnit}
     */
    public FortResponse readOrg(FortRequest request);

    /**
     * Commands searches existing OrgUnit entities from OrgUnit dataset.  The OrgUnit can be either User or Perm and is
     * set by setting type parameter on API.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.OrgUnit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.OrgUnit} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#name} - contains some or all of the chars associated with the OrgUnit objects targeted for search.</li>
     * <li>{@link us.jts.fortress.rbac.OrgUnit#type} - contains the type of OU:  {@link us.jts.fortress.rbac.OrgUnit.Type#USER} or {@link us.jts.fortress.rbac.OrgUnit.Type#PERM}</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to a List of type {@link us.jts.fortress.rbac.OrgUnit}
     */
    public FortResponse searchOrg(FortRequest request);

    // DelegatedAccessMgr

    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-assign URA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#userId} - contains the userId targeted for operation</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse canAssign(FortRequest request);

    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * User-Role Assignment (URA).  This adheres to the ARBAC02 functional specification for can-revoke URA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserRole#userId} - contains the userId targeted for operation</li>
     * <li>{@link us.jts.fortress.rbac.UserRole#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse canDeassign(FortRequest request);

    /**
     * This function will determine if the user contains an AdminRole that is authorized assignment control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-assign-p PRA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RolePerm} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.RolePerm} required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RolePerm#perm#objectName} - contains the permission object name targeted for operation</li>
     * <li>{@code us.jts.fortress.rbac.RolePerm#perm#opName} - contains the permission operation name targeted</li>
     * <li>{@code us.jts.fortress.rbac.RolePerm#role#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse canGrant(FortRequest request);

    /**
     * This function will determine if the user contains an AdminRole that is authorized revoke control over
     * Permission-Role Assignment (PRA).  This adheres to the ARBAC02 functional specification for can-revoke-p PRA.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.RolePerm} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.RolePerm} required parameters</h5>
     * <ul>
     * <li>{@code us.jts.fortress.rbac.RolePerm#perm#objectName} - contains the permission object name targeted for operation</li>
     * <li>{@code us.jts.fortress.rbac.RolePerm#perm#opName} - contains the permission operation name targeted</li>
     * <li>{@code us.jts.fortress.rbac.RolePerm#role#name} - contains the Role name targeted for operation.</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse canRevoke(FortRequest request);

    /**
     * This function returns a Boolean value meaning whether the subject of a given session is
     * allowed or not to perform a given operation on a given object. The function is valid if and
     * only if the session is a valid Fortress session, the object is a member of the OBJS data set,
     * and the operation is a member of the OPS data set. The session's subject has the permission
     * to perform the operation on that object if and only if that permission is assigned to (at least)
     * one of the session's active roles. This implementation will verify the roles or userId correspond
     * to the subject's active roles are registered in the object's access control list.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to admin {@link us.jts.fortress.rbac.Permission} entity</li>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <h5>{@link us.jts.fortress.rbac.Permission} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.Permission#objectName} - contains the name of existing admin object being targeted</li>
     * <li>{@link us.jts.fortress.rbac.Permission#opName} - contains the name of existing admin permission operation</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#isAuthorized} boolean will be 'true' if User authorized, otherwise 'false'.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse checkAdminAccess(FortRequest request);

    /**
     * This function adds an AdminRole as an active role of a session whose owner is a given user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAdminRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserAdminRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole} - contains the AdminRole name targeted for activation into User's session</li>
     * </ul>
     * </ul>
     * The function is valid if and only if:
     * <ul>
     * <li> the user is a member of the USERS data set
     * <li> the AdminRole is a member of the ADMINROLES data set
     * <li> the session is a valid Fortress session
     * <li> the user is authorized to that AdminRole
     * <li> the session is owned by that user.
     * </ul>
     * </p>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    public FortResponse addActiveAdminRole(FortRequest request);

    /**
     * This function deletes an AdminRole from the active role set of a session owned by a given user.
     * The function is valid if and only if the user is a member of the USERS data set, the
     * session object contains a valid Fortress session, the session is owned by the user,
     * and the AdminRole is an active role of that session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAdminRole} entity.</li>
     * <h5>{@link us.jts.fortress.rbac.UserRole} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAdminRole#name} - contains the AdminRole name targeted for removal from User's session</li>
     * </ul>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, Updated {@link FortResponse#session} will be included in response.
     */
    public FortResponse dropActiveAdminRole(FortRequest request);

    /**
     * This function returns the active admin roles associated with a session. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's RBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link us.jts.fortress.rbac.UserAdminRole}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse sessionAdminRoles(FortRequest request);

    /**
     * This function returns the ARBAC (administrative) permissions of the session, i.e., the admin permissions assigned
     * to its authorized admin roles. The function is valid if and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} containing a List of type {@link us.jts.fortress.rbac.Permission}.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse sessionAdminPermissions(FortRequest request);

    /**
     * This function returns the authorized ARBAC (administrative) roles associated with a session based on hierarchical relationships. The function is valid if
     * and only if the session is a valid Fortress session.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to User's ARBAC session that is created by calling {@link FortressServiceImpl#createSession} method before use in this service.</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#valueSet} containing a Set of type String containing role names authorized for User.  Updated {@link FortResponse#session} will be included in response as well.
     */
    public FortResponse authorizedSessionAdminRoles(FortRequest request);


    // PswdPolicyMgr

    /**
     * This method will add a new policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is not already present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} object</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being added.</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#minAge} - This attribute holds the number of seconds that must elapse between
     * modifications to the password.  If this attribute is not present, 0
     * seconds is assumed.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#maxAge} - This attribute holds the number of seconds after which a modified
     * password will expire. If this attribute is not present, or if the value is 0 the password
     * does not expire.  If not 0, the value must be greater than or equal
     * to the value of the pwdMinAge.
     * </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#inHistory} - This attribute specifies the maximum number of used passwords stored
     * in the pwdHistory attribute. If this attribute is not present, or if the value is 0, used
     * passwords are not stored in the pwdHistory attribute and thus may be reused.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#minLength} - When quality checking is enabled, this attribute holds the minimum
     * number of characters that must be used in a password.  If this
     * attribute is not present, no minimum password length will be
     * enforced.  If the server is unable to check the length (due to a
     * hashed password or otherwise), the server will, depending on the
     * value of the pwdCheckQuality attribute, either accept the password
     * without checking it ('0' or '1') or refuse it ('2').</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#expireWarning} - This attribute specifies the maximum number of seconds before a
     * password is due to expire that expiration warning messages will be
     * returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     * will be returned.  If not 0, the value must be smaller than the value
     * of the pwdMaxAge attribute.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#graceLoginLimit} - This attribute specifies the number of times an expired password can
     * be used to authenticate.  If this attribute is not present or if the
     * value is 0, authentication will fail. </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#lockout} - This attribute indicates, when its value is "TRUE", that the password
     * may not be used to authenticate after a specified number of
     * consecutive failed bind attempts.  The maximum number of consecutive
     * failed bind attempts is specified in pwdMaxFailure.  If this attribute is not present, or if the
     * value is "FALSE", the password may be used to authenticate when the number of failed bind
     * attempts has been reached.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#lockoutDuration} - This attribute holds the number of seconds that the password cannot
     * be used to authenticate due to too many failed bind attempts.  If
     * this attribute is not present, or if the value is 0 the password
     * cannot be used to authenticate until reset by a password
     * administrator.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#maxFailure} - This attribute specifies the number of consecutive failed bind
     * attempts after which the password may not be used to authenticate.
     * If this attribute is not present, or if the value is 0, this policy
     * is not checked, and the value of pwdLockout will be ignored.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#failureCountInterval} - This attribute holds the number of seconds after which the password
     * failures are purged from the failure counter, even though no
     * successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     * counter is only reset by a successful authentication.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#mustChange} - This attribute specifies with a value of "TRUE" that users must
     * change their passwords when they first bind to the directory after a
     * password is set or reset by a password administrator.  If this
     * attribute is not present, or if the value is "FALSE", users are not
     * required to change their password upon binding after the password
     * administrator sets or resets the password.  This attribute is not set
     * due to any actions specified by this document, it is typically set by
     * a password administrator after resetting a user's password.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#allowUserChange} - This attribute indicates whether users can change their own
     * passwords, although the change operation is still subject to access
     * control.  If this attribute is not present, a value of "TRUE" is
     * assumed.  This attribute is intended to be used in the absence of an access control mechanism.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#safeModify} - This attribute specifies whether or not the existing password must be
     * sent along with the new password when being changed.  If this
     * attribute is not present, a "FALSE" value is assumed.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#checkQuality} - This attribute indicates how the password quality will be verified
     * while being modified or added.  If this attribute is not present, or
     * if the value is '0', quality checking will not be enforced.  A value
     * of '1' indicates that the server will check the quality, and if the
     * server is unable to check it (due to a hashed password or other
     * reasons) it will be accepted.  A value of '2' indicates that the
     * server will check the quality, and if the server is unable to verify
     * it, it will return an error refusing the password. </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#attribute} - This holds the name of the attribute to which the password policy is
     * applied.  For example, the password policy may be applied to the
     * userPassword attribute </li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addPolicy(FortRequest request);

    /**
     * This method will update an exiting policy entry to the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} object</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being updated.</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#minAge} - This attribute holds the number of seconds that must elapse between
     * modifications to the password.  If this attribute is not present, 0
     * seconds is assumed.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#maxAge} - This attribute holds the number of seconds after which a modified
     * password will expire. If this attribute is not present, or if the value is 0 the password
     * does not expire.  If not 0, the value must be greater than or equal
     * to the value of the pwdMinAge.
     * </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#inHistory} - This attribute specifies the maximum number of used passwords stored
     * in the pwdHistory attribute. If this attribute is not present, or if the value is 0, used
     * passwords are not stored in the pwdHistory attribute and thus may be reused.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#minLength} - When quality checking is enabled, this attribute holds the minimum
     * number of characters that must be used in a password.  If this
     * attribute is not present, no minimum password length will be
     * enforced.  If the server is unable to check the length (due to a
     * hashed password or otherwise), the server will, depending on the
     * value of the pwdCheckQuality attribute, either accept the password
     * without checking it ('0' or '1') or refuse it ('2').</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#expireWarning} - This attribute specifies the maximum number of seconds before a
     * password is due to expire that expiration warning messages will be
     * returned to an authenticating user.  If this attribute is not present, or if the value is 0 no warnings
     * will be returned.  If not 0, the value must be smaller than the value
     * of the pwdMaxAge attribute.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#graceLoginLimit} - This attribute specifies the number of times an expired password can
     * be used to authenticate.  If this attribute is not present or if the
     * value is 0, authentication will fail. </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#lockout} - This attribute indicates, when its value is "TRUE", that the password
     * may not be used to authenticate after a specified number of
     * consecutive failed bind attempts.  The maximum number of consecutive
     * failed bind attempts is specified in pwdMaxFailure.  If this attribute is not present, or if the
     * value is "FALSE", the password may be used to authenticate when the number of failed bind
     * attempts has been reached.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#lockoutDuration} - This attribute holds the number of seconds that the password cannot
     * be used to authenticate due to too many failed bind attempts.  If
     * this attribute is not present, or if the value is 0 the password
     * cannot be used to authenticate until reset by a password
     * administrator.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#maxFailure} - This attribute specifies the number of consecutive failed bind
     * attempts after which the password may not be used to authenticate.
     * If this attribute is not present, or if the value is 0, this policy
     * is not checked, and the value of pwdLockout will be ignored.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#failureCountInterval} - This attribute holds the number of seconds after which the password
     * failures are purged from the failure counter, even though no
     * successful authentication occurred.  If this attribute is not present, or if its value is 0, the failure
     * counter is only reset by a successful authentication.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#mustChange} - This attribute specifies with a value of "TRUE" that users must
     * change their passwords when they first bind to the directory after a
     * password is set or reset by a password administrator.  If this
     * attribute is not present, or if the value is "FALSE", users are not
     * required to change their password upon binding after the password
     * administrator sets or resets the password.  This attribute is not set
     * due to any actions specified by this document, it is typically set by
     * a password administrator after resetting a user's password.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#allowUserChange} - This attribute indicates whether users can change their own
     * passwords, although the change operation is still subject to access
     * control.  If this attribute is not present, a value of "TRUE" is
     * assumed.  This attribute is intended to be used in the absence of an access control mechanism.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#safeModify} - This attribute specifies whether or not the existing password must be
     * sent along with the new password when being changed.  If this
     * attribute is not present, a "FALSE" value is assumed.</li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#checkQuality} - This attribute indicates how the password quality will be verified
     * while being modified or added.  If this attribute is not present, or
     * if the value is '0', quality checking will not be enforced.  A value
     * of '1' indicates that the server will check the quality, and if the
     * server is unable to check it (due to a hashed password or other
     * reasons) it will be accepted.  A value of '2' indicates that the
     * server will check the quality, and if the server is unable to verify
     * it, it will return an error refusing the password. </li>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#attribute} - This holds the name of the attribute to which the password policy is
     * applied.  For example, the password policy may be applied to the
     * userPassword attribute </li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updatePolicy(FortRequest request);

    /**
     * This method will delete exiting policy entry from the POLICIES data set.  This command is valid
     * if and only if the policy entry is already present in the POLICIES data set.  Existing users that
     * are assigned this policy will be removed from association.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} object</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - Maps to name attribute of pwdPolicy object class being removed.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deletePolicy(FortRequest request);

    /**
     * This method will return the password policy entity to the caller.  This command is valid
     * if and only if the policy entry is present in the POLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} entity</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entity} contains a reference to {@link us.jts.fortress.rbac.PwPolicy}
     */
    public FortResponse readPolicy(FortRequest request);

    /**
     * This method will return a list of all password policy entities that match a particular search string.
     * This command will return an empty list of no matching entries are found.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} entity</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - contains the name of existing object being targeted</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.PwPolicy}
     */
    public FortResponse searchPolicy(FortRequest request);

    /**
     * This method will associate a user entity with a password policy entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policyName refers to a
     * policy that is a member of the PWPOLICIES data set.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the userId targeted for update</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.PwPolicy} object</li>
     * <h5>{@link us.jts.fortress.rbac.PwPolicy} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.PwPolicy#name} - Maps to name attribute of pwdPolicy object class targeted for assignment.</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updateUserPolicy(FortRequest request);

    /**
     * This method will remove the pw policy assignment from a user entity.  This function is valid
     * if and only if the user is a member of the USERS data set and the policy attribute is assigned.
     * Removal of pw policy assignment will revert the user's policy to use the global default for OpenLDAP
     * instance that contains user.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the userId targeted for removal of policy assignment</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteUserPolicy(FortRequest request);

    // AuditMgr


    /**
     * This method returns a list of authentication audit events for a particular user {@link us.jts.fortress.rbac.UserAudit#userId},
     * and given timestamp field {@link us.jts.fortress.rbac.UserAudit#beginDate}.<BR>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#userId} - contains the target userId<</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.Bind}
     */
    public FortResponse searchBinds(FortRequest request);

    /**
     * This method returns a list of authorization events for a particular user {@link us.jts.fortress.rbac.UserAudit#userId}
     * and given timestamp field {@link us.jts.fortress.rbac.UserAudit#beginDate}.<BR>
     * Method also can discriminate between all events or failed only by setting {@link us.jts.fortress.rbac.UserAudit#failedOnly}.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#userId} - contains the target userId</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.AuthZ}
     */
    public FortResponse getUserAuthZs(FortRequest request);

    /**
     * This method returns a list of authorization events for a particular user {@link us.jts.fortress.rbac.UserAudit#userId},
     * object {@link us.jts.fortress.rbac.UserAudit#objName}, and given timestamp field {@link us.jts.fortress.rbac.UserAudit#beginDate}.<BR>
     * Method also can discriminate between all events or failed only by setting flag {@link us.jts.fortress.rbac.UserAudit#failedOnly}..
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#userId} - contains the target userId<</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#objName} - contains the object (authorization resource) name</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.AuthZ}
     */
    public FortResponse searchAuthZs(FortRequest request);

    /**
     * This method returns a list of sessions created for a given user {@link us.jts.fortress.rbac.UserAudit#userId},
     * and timestamp {@link us.jts.fortress.rbac.UserAudit#beginDate}.<BR>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} required parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#userId} - contains the target userId<</li>
     * </ul>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#beginDate} - contains the date in which to begin search</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.Mod}
     */
    public FortResponse searchUserSessions(FortRequest request);

    /**
     * This method returns a list of admin operations events for a particular entity {@link us.jts.fortress.rbac.UserAudit#dn},
     * object {@link us.jts.fortress.rbac.UserAudit#objName} and timestamp {@link us.jts.fortress.rbac.UserAudit#beginDate}.  If the internal
     * userId {@link us.jts.fortress.rbac.UserAudit#internalUserId} is set it will limit search by that field.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#dn} - contains the LDAP distinguished name for the updated object.  For example if caller
     * wants to find out what changes were made to John Doe's user object this would be 'uid=jdoe,ou=People,dc=example,dc=com'</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#objName} - contains the object (authorization resource) name corresponding to the event.  For example if caller
     * wants to return events where User object was modified, this would be 'updateUser'</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#internalUserId} - maps to the internalUserId of user who changed the record in LDAP.  This maps to {@link us.jts.fortress.rbac.User#internalId}.</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#endDate} - contains the date in which to end search</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.Mod}
     */
    public FortResponse searchAdminMods(FortRequest request);

    /**
     * This method returns a list of failed authentication attempts on behalf of an invalid identity {@link us.jts.fortress.rbac.UserAudit#userId},
     * and given timestamp {@link us.jts.fortress.rbac.UserAudit#beginDate}.  If the {@link us.jts.fortress.rbac.UserAudit#failedOnly} is true it will
     * return only authentication attempts made with invalid userId.  This event represents either User incorrectly entering userId during signon or
     * possible fraudulent logon attempt by hostile agent.
     * </p>
     * This event is generated when Fortress looks up User record prior to LDAP bind operation.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.UserAudit} entity</li>
     * <h5>{@link us.jts.fortress.rbac.UserAudit} optional parameters</h5>
     * <ul>
     * <li>{@link us.jts.fortress.rbac.UserAudit#userId} - contains the target userId</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#beginDate} - contains the date in which to begin search</li>
     * <li>{@link us.jts.fortress.rbac.UserAudit#failedOnly} - if set to 'true', return only failed authorization events</li>
     * </ul>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.AuthZ}
     */
    public FortResponse searchInvalidUsers(FortRequest request);

    // ConfigMgr


    /**
     * Create a new configuration node with given name and properties.  The name is required.  If node already exists,
     * a {@link us.jts.fortress.SecurityException} with error {@link us.jts.fortress.GlobalErrIds#FT_CONFIG_ALREADY_EXISTS} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Props} object</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse addConfig(FortRequest request);

    /**
     * Update existing configuration node with additional properties, or, replace existing properties.  The name is required.  If node does not exist,
     * a {@link us.jts.fortress.SecurityException} with error {@link us.jts.fortress.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for update</li>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Props} object</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse updateConfig(FortRequest request);

    /**
     * This service will either completely remove named configuration node from the directory or specified properties depending on the arguments passed in.
     * <p/>
     * <font size="3" color="red">
     * If properties are not passed in along with the name, this method will remove the configuration node completely from directory.<BR>
     * Care should be taken during execution to ensure target name is correct and permanent removal of all parameters located
     * there is intended.  There is no 'undo' for this operation.
     * </font>
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name of existing configuration node targeted for removal</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#entity} - contains a reference to {@link us.jts.fortress.rbac.Props} object. If this argument is passed service will remove only the properties listed</li>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}
     */
    public FortResponse deleteConfig(FortRequest request);

    /**
     * Read an existing configuration node with given name and return to caller.  The name is required.  If node doesn't exist,
     * a {@link us.jts.fortress.SecurityException} with error {@link us.jts.fortress.GlobalErrIds#FT_CONFIG_NOT_FOUND} will be thrown.
     * <h4>required parameters</h4>
     * <ul>
     * <li>{@link FortRequest#value} - contains the name to call the new configuration node</li>
     * </ul>
     * <h4>optional parameters</h4>
     * <ul>
     * <li>{@link FortRequest#session} - contains a reference to administrative session and if included service will enforce ARBAC constraints</li>
     * </ul>
     *
     * @param request contains a reference to {@code FortRequest}
     * @return reference to {@code FortResponse}, {@link FortResponse#entities} contains a reference to List of type {@link us.jts.fortress.rbac.Props}
     */
    public FortResponse readConfig(FortRequest request);
}