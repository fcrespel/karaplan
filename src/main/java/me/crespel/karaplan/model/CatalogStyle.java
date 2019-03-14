package me.crespel.karaplan.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "name"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogStyle implements Serializable {

	private static final long serialVersionUID = -2552799468243077340L;

	private Long id;
	private String name;
	private String img;

}
