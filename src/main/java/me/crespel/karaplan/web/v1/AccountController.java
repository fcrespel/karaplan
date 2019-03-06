package me.crespel.karaplan.web.v1;

import java.security.Principal;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
public class AccountController {

	@GetMapping("/principal")
	public Authentication getPrincipal(Principal p) {
		if (p instanceof Authentication) {
			return (Authentication) p;
		} else {
			return null;
		}
	}

}
