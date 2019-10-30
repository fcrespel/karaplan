package me.crespel.karaplan.security;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import com.fasterxml.jackson.annotation.JsonIgnore;

import me.crespel.karaplan.domain.User;

public class OidcUserWrapper implements OidcUser, UserWrapper {

	protected final OidcUser delegate;
	protected final User user;

	public OidcUserWrapper(OidcUser delegate, User user) {
		this.delegate = delegate;
		this.user = user;
	}

	public String getName() {
		return delegate.getName();
	}

	@JsonIgnore
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return delegate.getAuthorities();
	}

	@JsonIgnore
	public Map<String, Object> getAttributes() {
		return delegate.getAttributes();
	}

	@JsonIgnore
	public Map<String, Object> getClaims() {
		return delegate.getClaims();
	}

	@JsonIgnore
	public OidcUserInfo getUserInfo() {
		return delegate.getUserInfo();
	}

	@JsonIgnore
	public OidcIdToken getIdToken() {
		return delegate.getIdToken();
	}

	public User getUser() {
		return user;
	}

}
