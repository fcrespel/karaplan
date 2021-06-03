package me.crespel.karaplan.model.karafunremote;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunRemoteSongList {

	private Long count;
	private Long total;
	private List<KarafunRemoteSong> songs;

}
