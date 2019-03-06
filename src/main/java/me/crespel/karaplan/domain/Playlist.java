package me.crespel.karaplan.domain;

import java.util.Calendar;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
@EqualsAndHashCode(exclude = "songs")
@ToString(of = {"id", "name"})
@Entity
@EntityListeners(AuditingEntityListener.class)
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

	@ManyToMany
	@JoinTable(name = "playlist_song", joinColumns = { @JoinColumn(name = "FK_PLAYLIST", nullable = false) }, inverseJoinColumns = { @JoinColumn(name = "FK_SONG", nullable = false) })
	@JsonIgnoreProperties("playlists")
	private Set<Song> songs = Sets.newLinkedHashSet();

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "CREATED_DATE")
	private Calendar createdDate;

	@CreatedBy
	@ManyToOne
	@JoinColumn(name = "FK_USER_CREATED", referencedColumnName = "ID")
	private User createdBy;

	@LastModifiedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "UPDATED_DATE")
	private Calendar updatedDate;

	@LastModifiedBy
	@ManyToOne
	@JoinColumn(name = "FK_USER_UPDATED", referencedColumnName = "ID")
	private User updatedBy;

}
