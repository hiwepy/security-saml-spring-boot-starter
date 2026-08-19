package org.springframework.security.boot;

import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration for SAML web filter.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecuritySamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecuritySamlProperties.class })
public class SecuritySamlWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	/**
	 * Sets the application context.
	 *
	 * @param applicationContext the application context
	 * @throws BeansException if an error occurs
	 */
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	/**
	 * Returns the application context.
	 *
	 * @return the application context
	 */
	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
}
