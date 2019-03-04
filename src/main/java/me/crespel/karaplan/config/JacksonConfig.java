package me.crespel.karaplan.config;

import org.springframework.context.annotation.Bean;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.datatype.hibernate5.Hibernate5Module;

public class JacksonConfig {

	@Bean
	public Module hibernateModule() {
		return new Hibernate5Module();
	}

}
