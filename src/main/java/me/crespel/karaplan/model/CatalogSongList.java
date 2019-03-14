package me.crespel.karaplan.model;

import java.io.Serializable;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogSongList implements Serializable {

	private static final long serialVersionUID = -2300354696486480068L;

	private Long count;
	private Long total;
	private Set<CatalogSong> songs;

}
