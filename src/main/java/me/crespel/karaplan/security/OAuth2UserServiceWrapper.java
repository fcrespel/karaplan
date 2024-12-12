package me.crespel.karaplan.security;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.google.common.base.Strings;

import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.service.UserService;

public class OAuth2UserServiceWrapper implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;
	private final UserService userService;

	public OAuth2UserServiceWrapper(OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate, UserService userService) {
		this.delegate = delegate;
		this.userService = userService;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oauth2User = delegate.loadUser(userRequest);
		User user = syncUser(userRequest, oauth2User);
		return new OAuth2UserWrapper(oauth2User, user);
	}

	private User syncUser(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
		User user = userService.findByProviderAndUsername(userRequest.getClientRegistration().getRegistrationId(), oauth2User.getName())
				.orElse(new User().setProvider(userRequest.getClientRegistration().getRegistrationId()).setUsername(oauth2User.getName()));
		user.setEmail(getAttributeValue(oauth2User, "email"));
		if (Strings.isNullOrEmpty(user.getDisplayName())) {
			if (!Strings.isNullOrEmpty(getAttributeValue(oauth2User, "name"))) {
				user.setDisplayName(getAttributeValue(oauth2User, "name"));
			} else {
				user.setDisplayName(oauth2User.getName());
			}
		}
		return userService.save(user);
	}

	private String getAttributeValue(OAuth2User oauth2User, String attributeName) {
		Object value = oauth2User.getAttributes().get(attributeName);
		if (value instanceof String) {
			return (String) value;
		} else if (value instanceof Collection) {
			Iterator it = ((Collection) value).iterator();
			return it.hasNext() ? String.valueOf(it.next()) : null;
		} else if (value != null) {
			return value.toString();
		} else {
			return null;
		}
	}

}
