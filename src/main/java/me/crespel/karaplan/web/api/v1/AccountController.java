package me.crespel.karaplan.web.api.v1;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.security.UserWrapper;
import me.crespel.karaplan.service.SongService;
import me.crespel.karaplan.service.UserService;
import springfox.documentation.annotations.ApiIgnore;

@RestController
@RequestMapping(value = "/api/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "account", description = "Account management")
public class AccountController {

	@Autowired
	protected UserService userService;
	
	@Autowired
	protected SongService songService;
	
	@Resource
	private HttpServletRequest request;

	@GetMapping("/authentication")
	@ApiOperation("Get authentication info")
	public Authentication getAuthentication(@ApiIgnore Authentication auth) {
		return auth;
	}

	@GetMapping("/principal")
	@ApiOperation("Get the authenticated principal")
	public UserWrapper getPrincipal(@ApiIgnore @AuthenticationPrincipal UserWrapper userWrapper) {
		return userWrapper;
	}

	@GetMapping("/user")
	@ApiOperation("Get the authenticated user")
	public User getUser(@ApiIgnore @AuthenticationPrincipal UserWrapper userWrapper) {
		if (userWrapper != null) {
			return userWrapper.getUser();
		} else {
			return null;
		}
	}

	@PostMapping("/user")
	@ApiOperation("Update the authenticated user")
	public User updateUser(@RequestBody User user, @ApiIgnore @AuthenticationPrincipal UserWrapper userWrapper) {
		if (userWrapper != null) {
			User userToUpdate = userWrapper.getUser();
			userToUpdate.setDisplayName(user.getDisplayName());
			return userService.save(userToUpdate);
		} else {
			throw new BusinessException("Authentication is required");
		}
	}

	@DeleteMapping("/user")
	@ApiOperation("Delete the authenticated user")
	public void deleteUser(@RequestParam(required = false, defaultValue = "false") boolean deleteComments, @ApiIgnore @AuthenticationPrincipal UserWrapper userWrapper) {
		if (userWrapper != null) {
			userService.deleteAccount(deleteComments, userWrapper.getUser());
		} else {
			throw new BusinessException("Authentication is required"); 
		}
	}
	
}
