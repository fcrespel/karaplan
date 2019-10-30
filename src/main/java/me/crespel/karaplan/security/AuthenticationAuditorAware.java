package me.crespel.karaplan.security;

import java.util.Optional;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import me.crespel.karaplan.domain.User;

@Component
public class AuthenticationAuditorAware implements AuditorAware<User> {

	@Override
	public Optional<User> getCurrentAuditor() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof UserWrapper) {
			return Optional.of(((UserWrapper) authentication.getPrincipal()).getUser());
		} else {
			return Optional.empty();
		}
	}

}
