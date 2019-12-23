package kr.ejsoft.oauth2.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuthToken extends OAuthResponse {
	private String accessToken;

	private String tokenType;
	
	private int expriesIn;
	
	private String scope;
	
	private String refreshToken;

	@Override
	public String toString() {
		//
		StringBuilder builder = new StringBuilder();
		builder.append("TokenRequestResult [");
		if (error != null) {
			builder.append("error=");
			builder.append(error);
			builder.append(", errorDescription=");
			builder.append(errorDescription);
		} else {
			//
			builder.append("accessToken=");
			builder.append(accessToken);
			builder.append(", tokenType=");
			builder.append(tokenType);
			builder.append(", expriesIn=");
			builder.append(expriesIn);
			builder.append(", scope=");
			builder.append(scope);
			builder.append(", refreshToken=");
			builder.append(refreshToken);
		}
		builder.append("]");
		return builder.toString();
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getTokenType() {
		return tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public int getExpriesIn() {
		return expriesIn;
	}

	public void setExpriesIn(int expriesIn) {
		this.expriesIn = expriesIn;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getErrorDescription() {
		return errorDescription;
	}

	public void setErrorDescription(String errorDescription) {
		this.errorDescription = errorDescription;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
}
