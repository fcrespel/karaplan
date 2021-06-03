package me.crespel.karaplan.model.karafunremote;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "name", "artist"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunRemoteSong {

	private Long id;
	private String name;
	private KarafunRemoteArtist artist;
	private Long duration;
	private Integer year;
	private List<KarafunRemoteStyle> styles;
	private String img;
	private String lyrics;
	private String rights;

}
