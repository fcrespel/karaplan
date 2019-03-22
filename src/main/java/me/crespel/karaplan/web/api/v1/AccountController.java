package me.crespel.karaplan.web.api.v1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.security.OidcUserWrapper;
import me.crespel.karaplan.service.UserService;
import springfox.documentation.annotations.ApiIgnore;

@RestController
@RequestMapping(value = "/api/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "account", description = "Account management")
public class AccountController {

	@Autowired
	protected UserService userService;

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

	@PostMapping("/user")
	@ApiOperation("Update the authenticated user")
	public User updateUser(@RequestBody User user, @ApiIgnore @AuthenticationPrincipal OidcUserWrapper oidcUser) {
		User userToUpdate = oidcUser.getUser();
		userToUpdate.setDisplayName(user.getDisplayName());
		return userService.save(userToUpdate);
	}

}
