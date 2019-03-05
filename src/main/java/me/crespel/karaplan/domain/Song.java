package me.crespel.karaplan.domain;

import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = {"artist", "votes", "comments", "playlists"})
@ToString(of = {"id", "name"})
@Entity
@Table(name = "song")
@JsonIgnoreProperties(ignoreUnknown = true)
public class Song {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@Column(name = "CATALOG_ID", unique = true)
	private Long catalogId;

	@NotNull
	@Column(name = "NAME")
	private String name;

	@Column(name = "DURATION")
	private Long duration;

	@Column(name = "IMAGE")
	private String image;

	@ManyToOne
	@JsonIgnoreProperties("songs")
	private Artist artist;

	@OneToMany(mappedBy = "song")
	@JsonIgnoreProperties("song")
	private Set<SongVote> votes = Sets.newLinkedHashSet();

	@OneToMany(mappedBy = "song")
	@JsonIgnoreProperties("song")
	private Set<SongComment> comments = Sets.newLinkedHashSet();

	@ManyToMany
	@JsonIgnoreProperties("songs")
	private Set<Playlist> playlists = Sets.newLinkedHashSet();

}
