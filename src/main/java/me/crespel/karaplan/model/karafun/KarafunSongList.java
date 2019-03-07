package me.crespel.karaplan.model.karafun;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunSongList {

	private Long count;
	private Long total;
	private List<KarafunSong> songs;

}
