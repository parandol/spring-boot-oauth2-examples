package kr.ejsoft.oauth2.client.model;

public class OAuthResponse {
	protected String error;
	protected String errorDescription;

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
	public boolean isAccessTokenExpired() {
		if("invalid_token".equals(error) && errorDescription != null && errorDescription.indexOf("Access token expired") >= 0) {
			return true;
		}
		return false;
	}
	public boolean isRefreshTokenExpired() {
		if("invalid_token".equals(error) && errorDescription != null && errorDescription.indexOf("Refresh token expired") >= 0) {
			return true;
		}
		return false;
	}
}