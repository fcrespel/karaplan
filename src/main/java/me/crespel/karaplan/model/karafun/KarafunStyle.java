package me.crespel.karaplan.model.karafun;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;

@Data
@ToString(of = {"id", "name"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunStyle {

	private Long id;
	private String name;
	private String img;

}
