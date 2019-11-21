package kr.ejsoft.oauth2.server.model;

import java.sql.Timestamp;

public class OAuthApproval {
	private String userId;
	private String clientId;
	private String scope;
	private String status;
	private Timestamp expiresAt;
	private Timestamp lastModifiedAt;
	
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public Timestamp getExpiresAt() {
		return expiresAt;
	}
	public void setExpiresAt(Timestamp expiresAt) {
		this.expiresAt = expiresAt;
	}
	public void setExpiresAt(long time) {
		this.expiresAt = new Timestamp(time);
		
	}
	public Timestamp getLastModifiedAt() {
		return lastModifiedAt;
	}
	public void setLastModifiedAt(Timestamp lastModifiedAt) {
		this.lastModifiedAt = lastModifiedAt;
	}
	public void setLastModifiedAt(long time) {
		this.lastModifiedAt = new Timestamp(time);
	}
}
