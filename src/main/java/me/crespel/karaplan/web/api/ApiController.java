package me.crespel.karaplan.web.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import springfox.documentation.annotations.ApiIgnore;

@Controller
@ApiIgnore
public class ApiController {

	@RequestMapping("/api")
	public String index() {
		return "redirect:/swagger-ui/index.html";
	}

}
