package me.crespel.karaplan.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import com.google.common.base.Strings;

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
		if (Strings.isNullOrEmpty(user.getDisplayName())) {
			if (!Strings.isNullOrEmpty(oidcUser.getGivenName()) && !Strings.isNullOrEmpty(oidcUser.getFamilyName())) {
				user.setDisplayName(oidcUser.getGivenName() + " " + oidcUser.getFamilyName().charAt(0) + ".");
			} else if (!Strings.isNullOrEmpty(oidcUser.getFullName())) {
				user.setDisplayName(oidcUser.getFullName());
			} else if (!Strings.isNullOrEmpty(oidcUser.getPreferredUsername())) {
				user.setDisplayName(oidcUser.getPreferredUsername());
			} else {
				user.setDisplayName(oidcUser.getSubject());
			}
		}
		return userService.save(user);
	}

}
