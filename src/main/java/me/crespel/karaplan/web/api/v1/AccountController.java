package me.crespel.karaplan.web.api.v1;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import me.crespel.karaplan.security.OidcUserWrapper;
import springfox.documentation.annotations.ApiIgnore;

@RestController
@RequestMapping(value = "/api/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "account", description = "Account management")
public class AccountController {

	@GetMapping("/authentication")
	@ApiOperation("Get authentication info")
	public Authentication getAuthentication(@ApiIgnore Authentication auth) {
		return auth;
	}

	@GetMapping("/principal")
	@ApiOperation("Get the authenticated principal")
	public OidcUserWrapper getPrincipal(@ApiIgnore @AuthenticationPrincipal OidcUserWrapper oidcUser) {
		return oidcUser;
	}

}
