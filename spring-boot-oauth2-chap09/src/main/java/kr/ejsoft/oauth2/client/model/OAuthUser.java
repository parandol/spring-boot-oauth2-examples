package kr.ejsoft.oauth2.client.model;

public class OAuthUser extends OAuthResponse {
	private String username;

	private String name;

	private String icon;
	
	
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

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("OAuthUser [");
		if (error != null) {
			builder.append("error=");
			builder.append(error);
			builder.append(", errorDescription=");
			builder.append(errorDescription);
		} else {
			builder.append("username=");
			builder.append(username);
			builder.append(", name=");
			builder.append(name);
			builder.append(", icon=");
			builder.append(icon);
		}
		builder.append("]");
		return builder.toString();
	}
}