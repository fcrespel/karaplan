package me.crespel.karaplan.model.kv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;

@Data
@ToString(of = { "id", "name" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class KvArtist {

	private Long id;
	private String name;
	private String nameSorted;
	private String url;

}
