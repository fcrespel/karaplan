package me.crespel.karaplan.web;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/_ah")
public class AppEngineController {

	@RequestMapping("/start")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void start() {
	}

	@RequestMapping("/warmup")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void warmup() {
	}

}
