package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Set;
import java.util.SortedSet;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.SortComparator;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "members", "songs", "createdDate", "createdBy", "updatedDate", "updatedBy" })
@ToString(of = { "id", "name" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "playlist")
@JsonIgnoreProperties(ignoreUnknown = true)
public class Playlist implements Comparable<Playlist>, Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "NAME")
	private String name;

	@Column(name = "READ_ONLY")
	private Boolean readOnly;

	@JsonProperty(access = Access.READ_ONLY)
	@Column(name = "ACCESS_KEY")
	private String accessKey;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "playlist_user", joinColumns = { @JoinColumn(name = "FK_PLAYLIST", nullable = false) }, inverseJoinColumns = { @JoinColumn(name = "FK_USER", nullable = false) })
	private Set<User> members = Sets.newLinkedHashSet();

	@Column(name = "SONGS_COUNT")
	private Integer songsCount;

	@OneToMany(mappedBy = "key.playlist", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("playlist")
	@SortComparator(PlaylistSong.OrderByPlaylistAndPositionAndSongComparator.class)
	private SortedSet<PlaylistSong> songs = Sets.newTreeSet(PlaylistSong.orderByPlaylistAndPositionAndSongComparator);

	@Column(name = "COMMENTS_COUNT")
	private Integer commentsCount;

	@OneToMany(mappedBy = "playlist", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("playlist")
	@SortComparator(PlaylistComment.OrderByIdDescComparator.class)
	private SortedSet<PlaylistComment> comments = Sets.newTreeSet(PlaylistComment.orderByIdDescComparator);

	@Column(name = "DURATION")
	private Long duration;

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

	public void updateStats() {
		this.songsCount = (songs != null) ? songs.size() : 0;
		this.commentsCount = (comments != null) ? comments.size() : 0;
		this.duration = (songs != null) ? songs.stream().mapToLong(ps -> ps.getSong().getDuration()).sum() : 0;
	}

	@Override
	public int compareTo(Playlist o) {
		return orderByNameComparator.compare(this, o);
	}

	public static Comparator<Playlist> orderByIdComparator = new OrderByIdComparator();

	public static class OrderByIdComparator implements Comparator<Playlist>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Playlist o1, Playlist o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id, Ordering.natural().nullsLast())
					.result();
		}

	}

	public static Comparator<Playlist> orderByNameComparator = new OrderByNameComparator();

	public static class OrderByNameComparator implements Comparator<Playlist>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Playlist o1, Playlist o2) {
			return ComparisonChain.start()
					.compare(o1.name, o2.name, Ordering.natural().nullsLast())
					.compare(o1.id, o2.id, Ordering.natural().nullsLast())
					.result();
		}

	}

}
