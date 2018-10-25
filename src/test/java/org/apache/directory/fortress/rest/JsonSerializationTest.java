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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.directory.fortress.core.model.User;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class JsonSerializationTest {
    @Test
    public void testFqcn() throws Exception {
        User u = new User();
        JacksonFieldOnlyMapper om = new JacksonFieldOnlyMapper();
        byte[] data = om.writeValueAsBytes(u);
        JsonNode json = om.readTree(data);
        assertEquals(User.class.getName(), json.get("fqcn").asText());
        User read = om.readValue(data, User.class);
        assertNotNull(read);
    }
}
