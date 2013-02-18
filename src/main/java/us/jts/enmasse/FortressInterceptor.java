/*
 * Copyright (c) 2011-2013, JoshuaTree. All Rights Reserved.
 */
package us.jts.enmasse;

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


/**
 * Security Utility for EnMasse Server.
 *
 * @author Shawn McKinney
 */
public class FortressInterceptor extends SimpleAuthorizingInterceptor
{
    private static final String CLS_NM = FortressInterceptor.class.getName();
    private static final org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger(CLS_NM);

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

    /**
     *
     * @param name
     */
    public void setAnnotationClassName(String name)
    {
        try
        {
            log.info(CLS_NM + ".setAnnotationClassName:" + name);
            ClassLoaderUtils.loadClass(name, FortressInterceptor.class);
            annotationClassName = name;
        }
        catch (ClassNotFoundException ex)
        {
            String warning = CLS_NM + ".setAnnotationClassName caught ClassNotFoundException-" + ex;
            log.info((warning));
        }
    }

    /**
     *
     * @param object
     */
    public void setSecuredObject(Object object)
    {
        log.info(CLS_NM + ".setSecuredObject:" + object);
        Class<?> cls = ClassHelper.getRealClass(object);
        Map<String, String> rolesMap = new HashMap<String, String>();
        findRoles(cls, rolesMap);
        if (rolesMap.isEmpty())
        {
            log.info(CLS_NM + ".setSecuredObject The roles map is empty, the service object is not protected");
        }
        else if (log.isDebugEnabled())
        {
            for (Map.Entry<String, String> entry : rolesMap.entrySet())
            {
                log.debug(CLS_NM + ".setSecuredObject Method: " + entry.getKey() + ", roles: " + entry.getValue());
            }
        }
        super.setMethodRolesMap(rolesMap);
    }

    /**
     *
     * @param cls
     * @param rolesMap
     */
    protected void findRoles(Class<?> cls, Map<String, String> rolesMap)
    {
        log.info(CLS_NM + ".findRoles:" + rolesMap);
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

    /**
     *
     * @param anns
     * @param annName
     * @return String roles
     */
    private String getRoles(Annotation[] anns, String annName)
    {
        log.debug(CLS_NM + ".getRoles:" + annName);
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
                catch (java.lang.NoSuchMethodException ex)
                {
                    log.info(CLS_NM + ".getRoles annName=" + annName + ", caught NoSuchMethodException=" + ex);
                }
                catch (java.lang.IllegalAccessException ex)
                {
                    log.info(CLS_NM + ".getRoles annName=" + annName + ", caught IllegalAccessException=" + ex);
                }
                catch (InvocationTargetException ex)
                {
                    log.info(CLS_NM + ".getRoles annName=" + annName + ", caught InvocationTargetException=" + ex);
                }
                break;
            }
        }
        return null;
    }
}

