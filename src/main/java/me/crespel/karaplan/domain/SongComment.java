package me.crespel.karaplan.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = {"song", "user"})
@ToString(of = {"id", "comment"})
@Entity
@Table(name = "song_comment")
@JsonIgnoreProperties(ignoreUnknown = true)
public class SongComment {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@ManyToOne
	@JoinColumn(name = "FK_SONG", referencedColumnName = "ID")
	@JsonIgnoreProperties("comments")
	private Song song;

	@ManyToOne
	@JoinColumn(name = "FK_USER", referencedColumnName = "ID")
	@JsonIgnoreProperties("comments")
	private User user;

	@Column(name = "COMMENT")
	private String comment;

}
