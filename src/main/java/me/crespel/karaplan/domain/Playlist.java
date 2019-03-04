package me.crespel.karaplan.domain;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = "songs")
@ToString(of = {"id", "name"})
@Entity
@Table(name = "playlist")
@JsonIgnoreProperties(ignoreUnknown = true)
public class Playlist {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "NAME")
	private String name;

	@ManyToMany(mappedBy = "playlists")
	private Set<Song> songs = new LinkedHashSet<>();

}
