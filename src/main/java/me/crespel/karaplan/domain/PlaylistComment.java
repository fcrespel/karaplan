package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Comparator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "playlist", "user", "createdDate" })
@ToString(of = { "id", "comment" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "playlist_comment")
@JsonIgnoreProperties(ignoreUnknown = true)
public class PlaylistComment implements Comparable<PlaylistComment>, Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "COMMENT")
	private String comment;

	@NotNull
	@ManyToOne
	@JoinColumn(name = "FK_PLAYLIST", referencedColumnName = "ID")
	@JsonIgnoreProperties({ "songs", "comments" })
	private Playlist playlist;

	@CreatedBy
	@ManyToOne
	@JoinColumn(name = "FK_USER", referencedColumnName = "ID")
	@JsonIgnoreProperties({ "provider", "username", "firstName", "lastName", "fullName", "email", "locale", "votes", "comments", "playlists", "createdDate", "updatedDate" })
	private User user;

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "CREATED_DATE")
	private Calendar createdDate;

	@Override
	public int compareTo(PlaylistComment o) {
		return orderByIdDescComparator.compare(this, o);
	}

	public static Comparator<PlaylistComment> orderByIdDescComparator = new OrderByIdDescComparator();

	public static class OrderByIdDescComparator implements Comparator<PlaylistComment>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(PlaylistComment o1, PlaylistComment o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id, Ordering.natural().reverse().nullsFirst())
					.result();
		}

	}
}
