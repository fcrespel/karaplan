package me.crespel.karaplan.web.api.v1;

import java.security.Principal;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping(value = "/api/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "account", description = "Account management")
public class AccountController {

	@GetMapping("/principal")
	@ApiOperation("Get the authenticated principal")
	public Authentication getPrincipal(Principal p) {
		if (p instanceof Authentication) {
			return (Authentication) p;
		} else {
			return null;
		}
	}

}
