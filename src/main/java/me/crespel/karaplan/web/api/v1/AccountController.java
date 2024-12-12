package me.crespel.karaplan.web.api.v1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.security.UserWrapper;
import me.crespel.karaplan.service.UserService;

@RestController
@RequestMapping(value = "/api/v1/account", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "account", description = "Account management")
public class AccountController {

	@Autowired
	private UserService userService;

	@GetMapping("/authentication")
	@Operation(summary = "Get authentication info")
	public Authentication getAuthentication(Authentication auth) {
		return auth;
	}

	@GetMapping("/principal")
	@Operation(summary = "Get the authenticated principal")
	public UserWrapper getPrincipal(@AuthenticationPrincipal Object principal) {
		if (principal instanceof UserWrapper) {
			return (UserWrapper) principal;
		} else {
			return null;
		}
	}

	@GetMapping("/user")
	@Operation(summary = "Get the authenticated user")
	public User getUser(@AuthenticationPrincipal Object principal) {
		if (principal instanceof UserWrapper) {
			return ((UserWrapper) principal).getUser();
		} else {
			return null;
		}
	}

	@PostMapping("/user")
	@Operation(summary = "Update the authenticated user")
	public User updateUser(@RequestBody User user, @AuthenticationPrincipal Object principal) {
		if (principal instanceof UserWrapper) {
			User userToUpdate = ((UserWrapper) principal).getUser();
			userToUpdate.setDisplayName(user.getDisplayName());
			return userService.save(userToUpdate);
		} else {
			throw new BusinessException("Authentication is required");
		}
	}

	@DeleteMapping("/user")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	@Operation(summary = "Delete the authenticated user")
	public void deleteUser(@RequestParam(required = false, defaultValue = "false") boolean deleteComments, @AuthenticationPrincipal Object principal) {
		if (principal instanceof UserWrapper) {
			User userToDelete = ((UserWrapper) principal).getUser();
			userService.delete(userToDelete, deleteComments);
		} else {
			throw new BusinessException("Authentication is required"); 
		}
	}
	
}
