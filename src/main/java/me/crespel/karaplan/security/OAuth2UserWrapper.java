package me.crespel.karaplan.security;

import java.util.Collection;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import me.crespel.karaplan.domain.User;

public class OAuth2UserWrapper implements OAuth2User, UserWrapper {

	protected final OAuth2User delegate;
	protected final User user;

	public OAuth2UserWrapper(OAuth2User delegate, User user) {
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

	public User getUser() {
		return user;
	}

}
