package org.springframework.security.boot;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecuritySamlProperties.PREFIX)
public class SecuritySamlProperties {
	
	public static final String PREFIX = "spring.security.saml";
	
	/**
	 * Enable Security Ldap.
	 */
	private boolean enabled = false;
	
	private boolean useAuthenticationRequestCredentials = true;

	private String[] ldapUrls;
	
	/** The url of the LDAP server. */
	private String[] urls;
	
	private boolean pooled = false;

	private String groupSearchBase = "";

	private boolean anonymousReadOnly = false;

	private String referral = null;
	
	/** ldap://192.168.0.1:389/dc=gnetis,dc=com */
	private String providerUrl;
	
	/** cn=Manager,dc=gnetis,dc=com */
	private String userDn;
	
	private String password;
	
	/** The base suffix from which all operations should origin. If a base
	 * suffix is set, you will not have to (and, indeed, must not) specify the
	 * full distinguished names in any operations performed.  */
	private String base;
	
	private Map<String, Object> baseEnvironmentProperties;

	private boolean cacheEnvironmentProperties = true;
	
	/** FilterBasedLdapUserSearch */
	
	/** Context name to search in, relative to the base of the configured ContextSource. */
	private String searchBase = "";

	/**
	 * The filter expression used in the user search. This is an LDAP search filter (as
	 * defined in 'RFC 2254') with optional arguments. See the documentation for the
	 * <tt>search</tt> methods in {@link javax.naming.directory.DirContext DirContext} for
	 * more information.
	 *
	 * <p>
	 * In this case, the username is the only parameter.
	 * </p>
	 * Possible examples are:
	 * <ul>
	 * <li>(uid={0}) - this would search for a username match on the uid attribute.</li>
	 * </ul>
	 */
	private String searchFilter;
	
	/**The derefLinkFlag value as defined in SearchControls.. */
	private boolean derefLinkFlag;
	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates no
	 * attributes are returned.
	 */
	public String[] returningAttrs = new String[]{};
	/** If true then searches the entire subtree as identified by context, if false (the default) then only searches the level identified by the context. */
	private boolean searchSubtree;
	/** The time to wait before the search fails (in milliseconds); the default is zero, meaning forever. */
	private int searchTimeLimit;
	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}
	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	/**
	 * Returns the use authentication request credentials.
	 *
	 * @return the use authentication request credentials
	 */
	public boolean isUseAuthenticationRequestCredentials() {
		return useAuthenticationRequestCredentials;
	}
	/**
	 * Sets the use authentication request credentials.
	 *
	 * @param useAuthenticationRequestCredentials the use authentication request credentials
	 */
	public void setUseAuthenticationRequestCredentials(boolean useAuthenticationRequestCredentials) {
		this.useAuthenticationRequestCredentials = useAuthenticationRequestCredentials;
	}
	/**
	 * Returns the ldap urls.
	 *
	 * @return the ldap urls
	 */
	public String[] getLdapUrls() {
		return ldapUrls;
	}
	/**
	 * Sets the ldap urls.
	 *
	 * @param ldapUrls the ldap urls
	 */
	public void setLdapUrls(String[] ldapUrls) {
		this.ldapUrls = ldapUrls;
	}
	/**
	 * Returns the urls.
	 *
	 * @return the urls
	 */
	public String[] getUrls() {
		return urls;
	}
	/**
	 * Sets the urls.
	 *
	 * @param urls the urls
	 */
	public void setUrls(String[] urls) {
		this.urls = urls;
	}
	/**
	 * Returns the pooled.
	 *
	 * @return the pooled
	 */
	public boolean isPooled() {
		return pooled;
	}
	/**
	 * Sets the pooled.
	 *
	 * @param pooled the pooled
	 */
	public void setPooled(boolean pooled) {
		this.pooled = pooled;
	}
	/**
	 * Returns the group search base.
	 *
	 * @return the group search base
	 */
	public String getGroupSearchBase() {
		return groupSearchBase;
	}
	/**
	 * Sets the group search base.
	 *
	 * @param groupSearchBase the group search base
	 */
	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}
	/**
	 * Returns the anonymous read only.
	 *
	 * @return the anonymous read only
	 */
	public boolean isAnonymousReadOnly() {
		return anonymousReadOnly;
	}
	/**
	 * Sets the anonymous read only.
	 *
	 * @param anonymousReadOnly the anonymous read only
	 */
	public void setAnonymousReadOnly(boolean anonymousReadOnly) {
		this.anonymousReadOnly = anonymousReadOnly;
	}
	/**
	 * Returns the referral.
	 *
	 * @return the referral
	 */
	public String getReferral() {
		return referral;
	}
	/**
	 * Sets the referral.
	 *
	 * @param referral the referral
	 */
	public void setReferral(String referral) {
		this.referral = referral;
	}
	/**
	 * Returns the provider url.
	 *
	 * @return the provider url
	 */
	public String getProviderUrl() {
		return providerUrl;
	}
	/**
	 * Sets the provider url.
	 *
	 * @param providerUrl the provider url
	 */
	public void setProviderUrl(String providerUrl) {
		this.providerUrl = providerUrl;
	}
	/**
	 * Returns the user dn.
	 *
	 * @return the user dn
	 */
	public String getUserDn() {
		return userDn;
	}
	/**
	 * Sets the user dn.
	 *
	 * @param userDn the user dn
	 */
	public void setUserDn(String userDn) {
		this.userDn = userDn;
	}
	/**
	 * Returns the password.
	 *
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}
	/**
	 * Sets the password.
	 *
	 * @param password the password
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	/**
	 * Returns the base.
	 *
	 * @return the base
	 */
	public String getBase() {
		return base;
	}
	/**
	 * Sets the base.
	 *
	 * @param base the base
	 */
	public void setBase(String base) {
		this.base = base;
	}
	/**
	 * Returns the base environment properties.
	 *
	 * @return the base environment properties
	 */
	public Map<String, Object> getBaseEnvironmentProperties() {
		return baseEnvironmentProperties;
	}
	/**
	 * Sets the base environment properties.
	 *
	 * @param baseEnvironmentProperties the base environment properties
	 */
	public void setBaseEnvironmentProperties(Map<String, Object> baseEnvironmentProperties) {
		this.baseEnvironmentProperties = baseEnvironmentProperties;
	}
	/**
	 * Returns the cache environment properties.
	 *
	 * @return the cache environment properties
	 */
	public boolean isCacheEnvironmentProperties() {
		return cacheEnvironmentProperties;
	}
	/**
	 * Sets the cache environment properties.
	 *
	 * @param cacheEnvironmentProperties the cache environment properties
	 */
	public void setCacheEnvironmentProperties(boolean cacheEnvironmentProperties) {
		this.cacheEnvironmentProperties = cacheEnvironmentProperties;
	}
	/**
	 * Returns the search base.
	 *
	 * @return the search base
	 */
	public String getSearchBase() {
		return searchBase;
	}
	/**
	 * Sets the search base.
	 *
	 * @param searchBase the search base
	 */
	public void setSearchBase(String searchBase) {
		this.searchBase = searchBase;
	}
	/**
	 * Returns the search filter.
	 *
	 * @return the search filter
	 */
	public String getSearchFilter() {
		return searchFilter;
	}
	/**
	 * Sets the search filter.
	 *
	 * @param searchFilter the search filter
	 */
	public void setSearchFilter(String searchFilter) {
		this.searchFilter = searchFilter;
	}
	/**
	 * Returns the deref link flag.
	 *
	 * @return the deref link flag
	 */
	public boolean isDerefLinkFlag() {
		return derefLinkFlag;
	}
	/**
	 * Sets the deref link flag.
	 *
	 * @param derefLinkFlag the deref link flag
	 */
	public void setDerefLinkFlag(boolean derefLinkFlag) {
		this.derefLinkFlag = derefLinkFlag;
	}
	/**
	 * Returns the returning attrs.
	 *
	 * @return the returning attrs
	 */
	public String[] getReturningAttrs() {
		return returningAttrs;
	}
	/**
	 * Sets the returning attrs.
	 *
	 * @param returningAttrs the returning attrs
	 */
	public void setReturningAttrs(String[] returningAttrs) {
		this.returningAttrs = returningAttrs;
	}
	/**
	 * Returns the search subtree.
	 *
	 * @return the search subtree
	 */
	public boolean isSearchSubtree() {
		return searchSubtree;
	}
	/**
	 * Sets the search subtree.
	 *
	 * @param searchSubtree the search subtree
	 */
	public void setSearchSubtree(boolean searchSubtree) {
		this.searchSubtree = searchSubtree;
	}
	/**
	 * Returns the search time limit.
	 *
	 * @return the search time limit
	 */
	public int getSearchTimeLimit() {
		return searchTimeLimit;
	}
	/**
	 * Sets the search time limit.
	 *
	 * @param searchTimeLimit the search time limit
	 */
	public void setSearchTimeLimit(int searchTimeLimit) {
		this.searchTimeLimit = searchTimeLimit;
	}
	
 
    
	
    

}
