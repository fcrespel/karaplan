package me.crespel.karaplan.model.karafun;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunArtist {

	private Long id;
	private String name;

}
