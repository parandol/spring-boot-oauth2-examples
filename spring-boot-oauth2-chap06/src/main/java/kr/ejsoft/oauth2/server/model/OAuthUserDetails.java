package kr.ejsoft.oauth2.server.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;

@SuppressWarnings("serial")
public @Data class OAuthUserDetails implements UserDetails {

	private String username;
	private String password;
	private String authority;
	private boolean enabled;
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialsNonExpired;
	private String name;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
		auth.add(new SimpleGrantedAuthority(authority));
		return auth;
	}

//	public Collection<? extends GrantedAuthority> getAuthorities() {
//		ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
//		if(authority == null) return null;
//		String[] arr = authority.split(",");
//		if(arr != null && arr.length > 0) {
//			for(String e : arr) {
//				if(e == null || "".equals(e)) continue;
//				auth.add(new SimpleGrantedAuthority(e.trim()));
//			}
//		}
//		return auth;
//	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	public String getName() {
		return name;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder
			.append("OAuthUserDetails [")
			.append("username=").append(username)
			.append(", password=").append(password)
			.append(", authority=").append(authority)
			.append(", enabled=").append(enabled)
			.append(", accountNonExpired=").append(accountNonExpired)
			.append(", accountNonLocked=").append(accountNonLocked)
			.append(", credentialsNonExpired=").append(credentialsNonExpired)
			.append(", name=").append(name)
			.append("]");
		return builder.toString();
	}

}
