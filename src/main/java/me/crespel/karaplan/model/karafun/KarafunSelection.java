package me.crespel.karaplan.model.karafun;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "name"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunSelection {

	private Long id;
	private String name;
	private String img;

}
