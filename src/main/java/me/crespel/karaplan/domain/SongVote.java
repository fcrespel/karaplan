package me.crespel.karaplan.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = {"song", "user"})
@ToString(of = {"id", "score"})
@Entity
@Table(name = "song_vote")
@JsonIgnoreProperties(ignoreUnknown = true)
public class SongVote {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;
	
	@ManyToOne
	@JsonIgnoreProperties("votes")
	private Song song;

	@ManyToOne
	@JsonIgnoreProperties("votes")
	private User user;

	@Column(name = "SCORE")
	private Integer score;

}
