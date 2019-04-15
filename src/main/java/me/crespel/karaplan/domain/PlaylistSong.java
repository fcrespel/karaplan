package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Comparator;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "createdDate", "createdBy", "updatedDate", "updatedBy" })
@ToString(of = { "key", "position" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "playlist_song")
@JsonIgnoreProperties(ignoreUnknown = true)
public class PlaylistSong implements Comparable<PlaylistSong> {

	@JsonIgnore
	@EmbeddedId
	private PlaylistSongKey key = new PlaylistSongKey();

	@Column(name = "POSITION")
	private Long position;

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

	@JsonIgnoreProperties("songs")
	public Playlist getPlaylist() {
		return key != null ? key.getPlaylist() : null;
	}

	public PlaylistSong setPlaylist(Playlist playlist) {
		if (key == null) {
			key = new PlaylistSongKey();
		}
		key.setPlaylist(playlist);
		return this;
	}

	@JsonIgnoreProperties({ "votes", "comments" })
	public Song getSong() {
		return key != null ? key.getSong() : null;
	}

	public PlaylistSong setSong(Song song) {
		if (key == null) {
			key = new PlaylistSongKey();
		}
		key.setSong(song);
		return this;
	}

	@Override
	public int compareTo(PlaylistSong o) {
		return orderByPlaylistAndPositionAndSongComparator.compare(this, o);
	}

	public static Comparator<PlaylistSong> orderByPlaylistAndPositionAndSongComparator = new OrderByPlaylistAndPositionAndSongComparator();

	public static class OrderByPlaylistAndPositionAndSongComparator implements Comparator<PlaylistSong> {

		@Override
		public int compare(PlaylistSong o1, PlaylistSong o2) {
			return ComparisonChain.start()
					.compare(o1.key.playlist, o2.key.playlist, Ordering.natural().nullsFirst())
					.compare(o1.position, o2.position, Ordering.natural().nullsFirst())
					.compare(o1.key.song, o2.key.song, Ordering.natural().nullsFirst())
					.result();
		}

	}

	@Data
	@Accessors(chain = true)
	@Embeddable
	public static class PlaylistSongKey implements Serializable {

		private static final long serialVersionUID = -8046574858747808108L;

		@NotNull
		@ManyToOne(fetch = FetchType.EAGER)
		@JoinColumn(name = "FK_PLAYLIST", referencedColumnName = "ID")
		private Playlist playlist;

		@NotNull
		@ManyToOne(fetch = FetchType.EAGER, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
		@JoinColumn(name = "FK_SONG", referencedColumnName = "ID")
		private Song song;

	}

}
