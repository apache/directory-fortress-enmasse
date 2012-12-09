/*
 * Copyright (c) 2011-2012. Joshua Tree Software, LLC.  All Rights Reserved.
 */
package com.jts.enmasse;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.common.util.ClassHelper;
import org.apache.cxf.interceptor.security.SimpleAuthorizingInterceptor;


/**
 * Utility for EnMasse Server.
 *
 * @author Shawn McKinney
 * @created December 31, 2011
 */
public class FortressInterceptor extends SimpleAuthorizingInterceptor
{
    private static final Logger LOG = LogUtils.getL7dLogger(FortressInterceptor.class);
    private static final String DEFAULT_ANNOTATION_CLASS_NAME = "javax.annotation.security.RolesAllowed";
    private static final Set<String> SKIP_METHODS;

    static
    {
        SKIP_METHODS = new HashSet<String>();
        SKIP_METHODS.addAll(Arrays.asList(
            new String[]{"wait", "notify", "notifyAll",
                "equals", "toString", "hashCode"}));
    }

    private String annotationClassName = DEFAULT_ANNOTATION_CLASS_NAME;

    public void setAnnotationClassName(String name)
    {
        try
        {
            LOG.info("setAnnotationClassName:" + name);
            ClassLoaderUtils.loadClass(name, FortressInterceptor.class);
            annotationClassName = name;
        }
        catch (Throwable ex)
        {
            ex.printStackTrace();
            throw new IllegalArgumentException("Annotation class " + name + " is not available");
        }
    }

    public void setSecuredObject(Object object)
    {
        LOG.info("setSecuredObject:" + object);
        Class<?> cls = ClassHelper.getRealClass(object);
        Map<String, String> rolesMap = new HashMap<String, String>();
        findRoles(cls, rolesMap);
        if (rolesMap.isEmpty())
        {
            LOG.warning("The roles map is empty, the service object is not protected");
        }
        else if (LOG.isLoggable(Level.FINE))
        {
            for (Map.Entry<String, String> entry : rolesMap.entrySet())
            {
                LOG.fine("Method: " + entry.getKey() + ", roles: " + entry.getValue());
            }
        }
        super.setMethodRolesMap(rolesMap);
    }

    protected void findRoles(Class<?> cls, Map<String, String> rolesMap)
    {
        LOG.info("findRoles:" + rolesMap);
        if (cls == null || cls == Object.class)
        {
            return;
        }
        String classRolesAllowed = getRoles(cls.getAnnotations(), annotationClassName);
        for (Method m : cls.getMethods())
        {
            if (SKIP_METHODS.contains(m.getName()))
            {
                continue;
            }
            String methodRolesAllowed = getRoles(m.getAnnotations(), annotationClassName);
            String theRoles = methodRolesAllowed != null ? methodRolesAllowed : classRolesAllowed;
            if (theRoles != null)
            {
                rolesMap.put(m.getName(), theRoles);
            }
        }
        if (!rolesMap.isEmpty())
        {
            return;
        }

        findRoles(cls.getSuperclass(), rolesMap);

        if (!rolesMap.isEmpty())
        {
            return;
        }

        for (Class<?> interfaceCls : cls.getInterfaces())
        {
            findRoles(interfaceCls, rolesMap);
        }
    }

    private String getRoles(Annotation[] anns, String annName)
    {
        LOG.info("getRoles:" + annName);
        for (Annotation ann : anns)
        {
            if (ann.annotationType().getName().equals(annName))
            {
                try
                {
                    Method valueMethod = ann.annotationType().getMethod("value", new Class[]{});
                    String[] roles = (String[]) valueMethod.invoke(ann, new Object[]{});
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < roles.length; i++)
                    {
                        sb.append(roles[i]);
                        if (i + 1 < roles.length)
                        {
                            sb.append(" ");
                        }
                    }
                    return sb.toString();
                }
                catch (Exception ex)
                {
                    // ignore
                }
                break;
            }
        }
        return null;
    }
}

