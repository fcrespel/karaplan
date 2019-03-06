package me.crespel.karaplan.config;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.hibernate5.Hibernate5Module;

public class JacksonConfig {

	@Bean
	public Module simpleModule() {
		SimpleModule module = new SimpleModule();
		module.addAbstractTypeMapping(Set.class, LinkedHashSet.class);
		module.addAbstractTypeMapping(Map.class, LinkedHashMap.class);
		return module;
	}

	@Bean
	public Module hibernateModule() {
		return new Hibernate5Module();
	}

}
