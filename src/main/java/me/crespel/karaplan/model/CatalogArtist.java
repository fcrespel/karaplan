package me.crespel.karaplan.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogArtist implements Serializable {

	private static final long serialVersionUID = 487984812616477989L;

	private Long id;
	private String name;

}
