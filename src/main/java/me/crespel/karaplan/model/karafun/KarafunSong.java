package me.crespel.karaplan.model.karafun;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;

@Data
@ToString(of = {"id", "name", "artist"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunSong {

	private Long id;
	private String name;
	private KarafunArtist artist;
	private Long duration;
	private Long year;
	private List<KarafunStyle> styles;
	private String img;
	private String lyrics;
	private String rights;

}
