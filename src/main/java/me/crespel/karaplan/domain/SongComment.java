package me.crespel.karaplan.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = {"song", "user"})
@ToString(of = {"id", "comment"})
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "song_comment")
@JsonIgnoreProperties(ignoreUnknown = true)
public class SongComment {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "COMMENT")
	private String comment;

	@ManyToOne
	@JoinColumn(name = "FK_SONG", referencedColumnName = "ID")
	@JsonIgnoreProperties({"votes", "comments", "playlists"})
	private Song song;

	@CreatedBy
	@ManyToOne
	@JoinColumn(name = "FK_USER", referencedColumnName = "ID")
	@JsonIgnoreProperties({"votes", "comments", "playlists"})
	private User user;

}
