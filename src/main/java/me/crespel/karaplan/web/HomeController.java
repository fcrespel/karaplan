package me.crespel.karaplan.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping({
		"/",
		"/login",
		"/home/**",
		"/songs/**",
		"/playlists/**",
		"/user/**",
		"/about/**"
	})
	public String index() {
		return "index";
	}

}
