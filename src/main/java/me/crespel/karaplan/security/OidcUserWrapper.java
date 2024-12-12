package me.crespel.karaplan.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import me.crespel.karaplan.domain.User;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OidcUserWrapper implements OidcUser, UserWrapper, Serializable {

	private static final long serialVersionUID = 1L;

	private final OidcUser delegate;
	private final User user;

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
