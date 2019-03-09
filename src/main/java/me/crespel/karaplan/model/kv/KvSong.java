package me.crespel.karaplan.model.kv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "artistId", "name"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KvSong {

	private Long id;
	private Long artistId;
	private String name;
	private String url;
	private String previewUrl;
	private String imgUrl;
	private Long mp3Count;
	private Long wmvCount;
	private Long cdgCount;
	private Boolean hasMulti;
	private String multiUrl;
	private String dateAdded;

}
