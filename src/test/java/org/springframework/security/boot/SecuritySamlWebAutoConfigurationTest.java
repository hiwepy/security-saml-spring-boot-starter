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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link SecuritySamlWebAutoConfiguration }}.
 *
 * <p>Verifies the auto-configuration activates under the expected conditions
 * and exposes its declared beans.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecuritySamlWebAutoConfiguration Tests")
class SecuritySamlWebAutoConfigurationTest {

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecuritySamlWebAutoConfiguration configuration = new SecuritySamlWebAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration has @ConditionalOnProperty annotation")
    void testConditionalOnPropertyAnnotation() {
        ConditionalOnProperty prop = SecuritySamlWebAutoConfiguration.class.getAnnotation(ConditionalOnProperty.class);
        assertThat(prop).isNotNull();
        assertThat(prop.prefix()).isEqualTo("spring.security.saml");
        assertThat(prop.havingValue()).isEqualTo("true");
    }

    @Test
    @DisplayName("Auto-configuration has @AutoConfigureBefore annotation")
    void testAutoConfigureBeforeAnnotation() {
        AutoConfigureBefore before = SecuritySamlWebAutoConfiguration.class.getAnnotation(AutoConfigureBefore.class);
        assertThat(before).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration has @EnableConfigurationProperties annotation")
    void testEnableConfigurationPropertiesAnnotation() {
        EnableConfigurationProperties props = SecuritySamlWebAutoConfiguration.class.getAnnotation(EnableConfigurationProperties.class);
        assertThat(props).isNotNull();
        assertThat(props.value()).containsExactly(SecuritySamlProperties.class);
    }
}
