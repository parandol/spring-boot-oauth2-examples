package kr.ejsoft.oauth2.server.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import kr.ejsoft.oauth2.server.util.OAuthUtil;

@SuppressWarnings("serial")
public class OAuthClientDetails implements ClientDetails {

	private String clientId;
	private String clientSecret;
	private String scope;
	private String resourceIds;
	private boolean secretRequired;
	private boolean scoped;
	private String authorizedGrantTypes;
	private String redirectUris ;
	private String authorities;
	private String additionalInformation;
	private int accessTokenValidity;
	private int refreshTokenValidity;
	private boolean autoApprove;
	
	private String name;
	private String icon;
	private String description;
	
	@Override
	public String getClientId() {
		return clientId;
	}

	@Override
	public String getClientSecret() {
		return clientSecret;
	}
	
	public String getPassword() {
		return clientSecret;
	}

	@Override
	public Set<String> getResourceIds() {
		return OAuthUtil.toSet(resourceIds);
	}

	@Override
	public boolean isSecretRequired() {
		return secretRequired;
	}

	@Override
	public boolean isScoped() {
		return scoped;
	}

	@Override
	public Set<String> getScope() {
		return OAuthUtil.toSet(scope);
	}

	@Override
	public Set<String> getAuthorizedGrantTypes() {
		return OAuthUtil.toSet(authorizedGrantTypes);
	}

	@Override
	public Set<String> getRegisteredRedirectUri() {
		return OAuthUtil.toSet(redirectUris);
	}
	
	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
		auth.add(new SimpleGrantedAuthority(authorities));
		return auth;
	}

	@Override
	public Integer getAccessTokenValiditySeconds() {
		return accessTokenValidity;
	}

	@Override
	public Integer getRefreshTokenValiditySeconds() {
		return refreshTokenValidity;
	}

	@Override
	public boolean isAutoApprove(String scope) {
		return autoApprove;
	}

	@Override
	public Map<String, Object> getAdditionalInformation() {
//		return additionalInformation;
		return null;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getIcon() {
		return icon;
	}

	public void setIcon(String icon) {
		this.icon = icon;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder
			.append("OAuthClientDetails [")
			.append("clientId=").append(clientId)
			.append(", clientSecret=").append(clientSecret)
			.append(", scope=").append(scope)
			.append(", resourceIds=").append(resourceIds)
			.append(", secretRequired=").append(secretRequired)
			.append(", scoped=").append(scoped)
			.append(", authorizedGrantTypes=").append(authorizedGrantTypes)
			.append(", authorities=").append(authorities)
			.append(", redirectUris=").append(redirectUris)
			.append(", accessTokenValidity=").append(accessTokenValidity)
			.append(", refreshTokenValidity=").append(refreshTokenValidity)
			.append(", additionalInformation=").append(additionalInformation)
			.append("]");
		return builder.toString();
	}
}
