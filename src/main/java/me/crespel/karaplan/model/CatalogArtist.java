package me.crespel.karaplan.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogArtist {

	private Long id;
	private String name;

}
