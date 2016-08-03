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

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.apache.cxf.common.util.ClassHelper;
import org.apache.cxf.interceptor.security.SimpleAuthorizingInterceptor;
import org.apache.log4j.Logger;


/**
 * Security Utility for Fortress Rest Server.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FortressInterceptor extends SimpleAuthorizingInterceptor
{
    /** A logger for this class */
    private static final Logger LOG = Logger.getLogger(FortressInterceptor.class.getName());

    private static final String DEFAULT_ANNOTATION_CLASS_NAME = "javax.annotation.security.RolesAllowed";
    
    /** The list of methods we want to skip */
    private static final Set<String> SKIP_METHODS;

    static
    {
        SKIP_METHODS = new HashSet<String>();
        SKIP_METHODS.addAll( Arrays.asList(
            new String[]{ "wait", "notify", "notifyAll",
                "equals", "toString", "hashCode" } ) );
    }

    private String annotationClassName = DEFAULT_ANNOTATION_CLASS_NAME;

    /**
     *
     * @param name The annotation class name
     */
    public void setAnnotationClassName( String name )
    {
        try
        {
            LOG.info( "FortressInterceptor.setAnnotationClassName:" + name );
            ClassLoaderUtils.loadClass( name, FortressInterceptor.class );
            annotationClassName = name;
        }
        catch ( ClassNotFoundException ex )
        {
            LOG.info( "FortressInterceptor.setAnnotationClassName caught ClassNotFoundException-" + ex );
        }
    }
    

    /**
     *
     * @param object The Object to secure
     */
    public void setSecuredObject( Object object )
    {
        LOG.info( "FortressInterceptor.setSecuredObject:" + object );
        Class<?> cls = ClassHelper.getRealClass( object );
        Map<String, String> rolesMap = new HashMap<String, String>();
        findRoles( cls, rolesMap );
        
        if ( rolesMap.isEmpty() )
        {
            LOG.info( "FortressInterceptor.setSecuredObject The roles map is empty, the service object is not protected" );
        }
        else if ( LOG.isDebugEnabled() )
        {
            for ( Map.Entry<String, String> entry : rolesMap.entrySet() )
            {
                LOG.debug( "FortressInterceptor.setSecuredObject Method: " + entry.getKey() + ", roles: " + entry.getValue() );
            }
        }
        
        super.setMethodRolesMap( rolesMap );
    }
    

    /**
     * Find the list of 
     * @param cls The class for which we want to find roles
     * @param rolesMap The Map containing the roles
     */
    protected void findRoles( Class<?> cls, Map<String, String> rolesMap )
    {
        LOG.info( "FortressInterceptor.findRoles:" + rolesMap );
        
        if ( ( cls == null ) || ( cls == Object.class ) )
        {
            return;
        }
        
        String classRolesAllowed = getRoles( cls.getAnnotations(), annotationClassName );
        
        // Process all the methods for the given class itself
        for ( Method m : cls.getMethods() )
        {
            if ( SKIP_METHODS.contains( m.getName() ) )
            {
                continue;
            }
            
            String methodRolesAllowed = getRoles( m.getAnnotations(), annotationClassName );
            
            if ( methodRolesAllowed != null )
            {
                rolesMap.put( m.getName(), methodRolesAllowed );
            }
            else if ( classRolesAllowed != null )
            {
                rolesMap.put( m.getName(), classRolesAllowed );
            }
        }
        
        // We have found roles in the current class, get out
        if ( !rolesMap.isEmpty() )
        {
            return;
        }

        // Chekc the super class now
        findRoles( cls.getSuperclass(), rolesMap );

        // Get out if we have some roles
        if ( !rolesMap.isEmpty() )
        {
            return;
        }

        // Still nothing ? let's check the interfaces
        for ( Class<?> interfaceCls : cls.getInterfaces() )
        {
            findRoles( interfaceCls, rolesMap );
        }
    }

    
    /**
     *
     * @param anns
     * @param annName
     * @return String roles
     */
    private String getRoles( Annotation[] anns, String annName )
    {
        LOG.debug( "FortressInterceptor.getRoles:" + annName );
        
        for ( Annotation ann : anns )
        {
            if ( ann.annotationType().getName().equals( annName ) )
            {
                try
                {
                    Method valueMethod = ann.annotationType().getMethod( "value", new Class[]{} );
                    String[] roles = (String[]) valueMethod.invoke( ann, new Object[]{} );
                    StringBuilder sb = new StringBuilder();
                    boolean isFirst = false;
                    
                    for ( String role : roles )
                    {
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            sb.append( " " );
                        }
                        
                        sb.append( role );
                    }
                    
                    return sb.toString();
                }
                catch ( NoSuchMethodException ex )
                {
                    LOG.info( "FortressInterceptor.getRoles annName=" + annName + ", caught NoSuchMethodException=" + ex );
                }
                catch ( IllegalAccessException ex )
                {
                    LOG.info( "FortressInterceptor.getRoles annName=" + annName + ", caught IllegalAccessException=" + ex );
                }
                catch ( InvocationTargetException ex )
                {
                    LOG.info( "FortressInterceptor.getRoles annName=" + annName + ", caught InvocationTargetException=" + ex );
                }
                break;
            }
        }
        
        return null;
    }
}

