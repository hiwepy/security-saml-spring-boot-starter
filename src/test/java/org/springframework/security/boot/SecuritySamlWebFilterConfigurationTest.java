/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {{ @link SecuritySamlWebFilterConfiguration }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecuritySamlWebFilterConfiguration Tests")
class SecuritySamlWebFilterConfigurationTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        SecuritySamlWebFilterConfiguration instance = new SecuritySamlWebFilterConfiguration();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Configuration implements ApplicationContextAware")
    void testImplementsApplicationContextAware() {
        assertThat(ApplicationContextAware.class.isAssignableFrom(SecuritySamlWebFilterConfiguration.class)).isTrue();
    }

    @Test
    @DisplayName("setApplicationContext and getApplicationContext work correctly")
    void testApplicationContextMethods() {
        SecuritySamlWebFilterConfiguration config = new SecuritySamlWebFilterConfiguration();
        ApplicationContext ctx = mock(ApplicationContext.class);
        config.setApplicationContext(ctx);
        assertThat(config.getApplicationContext()).isSameAs(ctx);
    }

    @Test
    @DisplayName("getApplicationContext returns null initially")
    void testGetApplicationContextInitiallyNull() {
        SecuritySamlWebFilterConfiguration config = new SecuritySamlWebFilterConfiguration();
        assertThat(config.getApplicationContext()).isNull();
    }

    @Test
    @DisplayName("Configuration has @ConditionalOnProperty annotation")
    void testConditionalOnPropertyAnnotation() {
        ConditionalOnProperty prop = SecuritySamlWebFilterConfiguration.class.getAnnotation(ConditionalOnProperty.class);
        assertThat(prop).isNotNull();
        assertThat(prop.prefix()).isEqualTo("spring.security.saml");
        assertThat(prop.havingValue()).isEqualTo("true");
    }

    @Test
    @DisplayName("Configuration has @AutoConfigureBefore annotation")
    void testAutoConfigureBeforeAnnotation() {
        AutoConfigureBefore before = SecuritySamlWebFilterConfiguration.class.getAnnotation(AutoConfigureBefore.class);
        assertThat(before).isNotNull();
    }

    @Test
    @DisplayName("Configuration has @EnableConfigurationProperties annotation")
    void testEnableConfigurationPropertiesAnnotation() {
        EnableConfigurationProperties props = SecuritySamlWebFilterConfiguration.class.getAnnotation(EnableConfigurationProperties.class);
        assertThat(props).isNotNull();
    }
}
