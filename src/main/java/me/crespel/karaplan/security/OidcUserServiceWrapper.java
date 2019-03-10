package me.crespel.karaplan.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.service.UserService;

public class OidcUserServiceWrapper implements OAuth2UserService<OidcUserRequest, OidcUser> {

	protected final OAuth2UserService<OidcUserRequest, OidcUser> delegate;

	@Autowired
	protected UserService userService;

	public OidcUserServiceWrapper(OAuth2UserService<OidcUserRequest, OidcUser> delegate) {
		this.delegate = delegate;
	}

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		OidcUser oidcUser = delegate.loadUser(userRequest);
		User user = syncUser(oidcUser);
		return new OidcUserWrapper(oidcUser, user);
	}

	protected User syncUser(OidcUser oidcUser) {
		User user = userService.findByUsername(oidcUser.getSubject()).orElse(new User().setUsername(oidcUser.getSubject()))
				.setFirstName(oidcUser.getGivenName())
				.setLastName(oidcUser.getFamilyName())
				.setFullName(oidcUser.getFullName())
				.setEmail(oidcUser.getEmail());
		return userService.save(user);
	}

}
