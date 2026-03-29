package me.crespel.karaplan.config;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.datatype.hibernate7.Hibernate7Module;

@Configuration
public class JacksonConfig {

	@Bean
	public JacksonModule simpleModule() {
		SimpleModule module = new SimpleModule();
		module.addAbstractTypeMapping(Set.class, LinkedHashSet.class);
		module.addAbstractTypeMapping(Map.class, LinkedHashMap.class);
		return module;
	}

	@Bean
	public JacksonModule hibernateModule() {
		Hibernate7Module module = new Hibernate7Module();
		module.disable(Hibernate7Module.Feature.USE_TRANSIENT_ANNOTATION);
		return module;
	}

}
