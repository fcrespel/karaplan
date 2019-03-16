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
public class CatalogSelection implements Serializable {

	private static final long serialVersionUID = -2595089354908324339L;

	private Long id;
	private String name;
	private String img;

}
