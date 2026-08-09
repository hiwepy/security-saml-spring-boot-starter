package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration for SAML-based security.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 */
@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecuritySamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecuritySamlProperties.class })
public class SecuritySamlWebAutoConfiguration {

}
