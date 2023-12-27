package me.crespel.karaplan.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;

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
	public ModelAndView index(HttpServletRequest req) {
		ModelAndView model = new ModelAndView("index");
		model.addObject("baseUrl", ServletUriComponentsBuilder.fromRequest(req).replacePath("").toUriString());
		model.addObject("currentUrl", ServletUriComponentsBuilder.fromRequest(req).toUriString());
		return model;
	}

}
