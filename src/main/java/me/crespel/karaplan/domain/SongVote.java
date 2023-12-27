package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Comparator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotNull;

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
@EqualsAndHashCode(exclude = { "song", "user", "createdDate" })
@ToString(of = { "id", "score" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "song_vote", uniqueConstraints = @UniqueConstraint(columnNames = { "FK_SONG", "FK_USER" }))
@JsonIgnoreProperties(ignoreUnknown = true)
public class SongVote implements Comparable<SongVote>, Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "SCORE")
	private Integer score;

	@NotNull
	@ManyToOne
	@JoinColumn(name = "FK_SONG", referencedColumnName = "ID")
	@JsonIgnoreProperties({ "votes", "comments", "playlists" })
	private Song song;

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
	public int compareTo(SongVote o) {
		return orderByIdDescComparator.compare(this, o);
	}

	public static Comparator<SongVote> orderByIdDescComparator = new OrderByIdDescComparator();

	public static class OrderByIdDescComparator implements Comparator<SongVote>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(SongVote o1, SongVote o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id, Ordering.natural().reverse().nullsFirst())
					.result();
		}

	}

}
