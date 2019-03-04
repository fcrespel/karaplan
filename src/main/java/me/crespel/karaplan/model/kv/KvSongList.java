package me.crespel.karaplan.model.kv;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KvSongList {

	private Long totalLength;
	private Long length;
	private Set<KvSong> songs;

}
