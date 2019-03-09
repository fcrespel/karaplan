package me.crespel.karaplan.web.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import springfox.documentation.annotations.ApiIgnore;

@Controller
@RequestMapping("/api")
@ApiIgnore
public class ApiController {

	@RequestMapping("/")
	public String index() {
		return "redirect:/swagger-ui.html";
	}

}
