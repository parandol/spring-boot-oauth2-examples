package kr.ejsoft.oauth2.client.model;

public class User {
	private String username;
	private String name;
	private String icon;
	private String accessToken;
	private String refreshToken;
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
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
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public void set(OAuthUser oauthUser) {
		this.username = oauthUser.getUsername();
		this.name = oauthUser.getName();
		this.icon = oauthUser.getIcon();
	}
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("User [username=");
		builder.append(username);
		builder.append(", name=");
		builder.append(name);
		builder.append(", icon=");
		builder.append(icon);
		builder.append(", accessToken=");
		builder.append(accessToken);
		builder.append(", refreshToken=");
		builder.append(refreshToken);
		builder.append("]");
		return builder.toString();
	}
}