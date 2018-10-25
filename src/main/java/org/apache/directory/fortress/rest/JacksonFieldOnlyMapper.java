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

import org.apache.directory.fortress.core.model.FortEntity;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This class is used to marshall/unmarshall subtypes of {@link FortEntity} using only the fields.
 * This mapper ignores all the getter and setters.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class JacksonFieldOnlyMapper extends ObjectMapper
{
    public JacksonFieldOnlyMapper()
    {
        super();
        // allow access to fields
        setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
        setVisibility(PropertyAccessor.GETTER, Visibility.NONE); // and do not use getters and setters
        setVisibility(PropertyAccessor.IS_GETTER, Visibility.NONE);
        setVisibility(PropertyAccessor.SETTER, Visibility.NONE);
    }
}
