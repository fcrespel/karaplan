package me.crespel.karaplan.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;

@Data
@ToString(of = {"id", "name"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogStyle {

	private Long id;
	private String name;
	private String img;

}
