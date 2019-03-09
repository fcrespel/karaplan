package me.crespel.karaplan.model;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogSongList {

	private Long count;
	private Long total;
	private Set<CatalogSong> songs;

}
