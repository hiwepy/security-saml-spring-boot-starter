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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link SecuritySamlProperties }}.
 *
 * <p>Verifies default values, getters/setters and POJO contract.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecuritySamlProperties Tests")
class SecuritySamlPropertiesTest {

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("Field 'enabled' can be set and read")
    void testEnabledField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Field 'useAuthenticationRequestCredentials' can be set and read")
    void testUseAuthenticationRequestCredentialsField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isUseAuthenticationRequestCredentials()).isTrue();
        props.setUseAuthenticationRequestCredentials(false);
        assertThat(props.isUseAuthenticationRequestCredentials()).isFalse();
    }

    @Test
    @DisplayName("Field 'ldapUrls' can be set and read")
    void testLdapUrlsField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getLdapUrls()).isNull();
        String[] urls = {"ldap://localhost:389"};
        props.setLdapUrls(urls);
        assertThat(props.getLdapUrls()).containsExactly("ldap://localhost:389");
    }

    @Test
    @DisplayName("Field 'urls' can be set and read")
    void testUrlsField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getUrls()).isNull();
        String[] urls = {"ldap://localhost:389"};
        props.setUrls(urls);
        assertThat(props.getUrls()).containsExactly("ldap://localhost:389");
    }

    @Test
    @DisplayName("Field 'pooled' can be set and read")
    void testPooledField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isPooled()).isFalse();
        props.setPooled(true);
        assertThat(props.isPooled()).isTrue();
    }

    @Test
    @DisplayName("Field 'groupSearchBase' can be set and read")
    void testGroupSearchBaseField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getGroupSearchBase()).isEqualTo("");
        props.setGroupSearchBase("ou=groups");
        assertThat(props.getGroupSearchBase()).isEqualTo("ou=groups");
    }

    @Test
    @DisplayName("Field 'anonymousReadOnly' can be set and read")
    void testAnonymousReadOnlyField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isAnonymousReadOnly()).isFalse();
        props.setAnonymousReadOnly(true);
        assertThat(props.isAnonymousReadOnly()).isTrue();
    }

    @Test
    @DisplayName("Field 'referral' can be set and read")
    void testReferralField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getReferral()).isNull();
        props.setReferral("follow");
        assertThat(props.getReferral()).isEqualTo("follow");
    }

    @Test
    @DisplayName("Field 'providerUrl' can be set and read")
    void testProviderUrlField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getProviderUrl()).isNull();
        props.setProviderUrl("ldap://localhost:389/dc=example,dc=com");
        assertThat(props.getProviderUrl()).isEqualTo("ldap://localhost:389/dc=example,dc=com");
    }

    @Test
    @DisplayName("Field 'userDn' can be set and read")
    void testUserDnField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getUserDn()).isNull();
        props.setUserDn("cn=admin");
        assertThat(props.getUserDn()).isEqualTo("cn=admin");
    }

    @Test
    @DisplayName("Field 'password' can be set and read")
    void testPasswordField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getPassword()).isNull();
        props.setPassword("secret");
        assertThat(props.getPassword()).isEqualTo("secret");
    }

    @Test
    @DisplayName("Field 'base' can be set and read")
    void testBaseField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getBase()).isNull();
        props.setBase("dc=example,dc=com");
        assertThat(props.getBase()).isEqualTo("dc=example,dc=com");
    }

    @Test
    @DisplayName("Field 'baseEnvironmentProperties' can be set and read")
    void testBaseEnvironmentPropertiesField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getBaseEnvironmentProperties()).isNull();
        Map<String, Object> envProps = new HashMap<>();
        envProps.put("key", "value");
        props.setBaseEnvironmentProperties(envProps);
        assertThat(props.getBaseEnvironmentProperties()).containsEntry("key", "value");
    }

    @Test
    @DisplayName("Field 'cacheEnvironmentProperties' can be set and read")
    void testCacheEnvironmentPropertiesField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isCacheEnvironmentProperties()).isTrue();
        props.setCacheEnvironmentProperties(false);
        assertThat(props.isCacheEnvironmentProperties()).isFalse();
    }

    @Test
    @DisplayName("Field 'searchBase' can be set and read")
    void testSearchBaseField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getSearchBase()).isEqualTo("");
        props.setSearchBase("ou=users");
        assertThat(props.getSearchBase()).isEqualTo("ou=users");
    }

    @Test
    @DisplayName("Field 'searchFilter' can be set and read")
    void testSearchFilterField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getSearchFilter()).isNull();
        props.setSearchFilter("(uid={0})");
        assertThat(props.getSearchFilter()).isEqualTo("(uid={0})");
    }

    @Test
    @DisplayName("Field 'derefLinkFlag' can be set and read")
    void testDerefLinkFlagField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isDerefLinkFlag()).isFalse();
        props.setDerefLinkFlag(true);
        assertThat(props.isDerefLinkFlag()).isTrue();
    }

    @Test
    @DisplayName("Field 'returningAttrs' can be set and read")
    void testReturningAttrsField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getReturningAttrs()).isEmpty();
        String[] attrs = {"cn", "mail"};
        props.setReturningAttrs(attrs);
        assertThat(props.getReturningAttrs()).containsExactly("cn", "mail");
    }

    @Test
    @DisplayName("Field 'searchSubtree' can be set and read")
    void testSearchSubtreeField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.isSearchSubtree()).isFalse();
        props.setSearchSubtree(true);
        assertThat(props.isSearchSubtree()).isTrue();
    }

    @Test
    @DisplayName("Field 'searchTimeLimit' can be set and read")
    void testSearchTimeLimitField() {
        SecuritySamlProperties props = new SecuritySamlProperties();
        assertThat(props.getSearchTimeLimit()).isEqualTo(0);
        props.setSearchTimeLimit(5000);
        assertThat(props.getSearchTimeLimit()).isEqualTo(5000);
    }

    @Test
    @DisplayName("Public constant 'PREFIX' has expected value")
    void testPREFIXConstant() {
        assertThat(SecuritySamlProperties.PREFIX).isEqualTo("spring.security.saml");
    }
}
