package me.crespel.karaplan.model;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "name", "artist"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogSong {

	private Long id;
	private String name;
	private CatalogArtist artist;
	private Long duration;
	private Long year;
	private Set<CatalogStyle> styles;
	private String img;
	private String lyrics;
	private String rights;

}
