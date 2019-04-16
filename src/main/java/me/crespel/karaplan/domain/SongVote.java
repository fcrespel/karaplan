package me.crespel.karaplan.domain;

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
import javax.persistence.UniqueConstraint;
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
@EqualsAndHashCode(exclude = { "song", "user", "createdDate" })
@ToString(of = { "id", "score" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "song_vote", uniqueConstraints = @UniqueConstraint(columnNames = { "FK_SONG", "FK_USER" }))
@JsonIgnoreProperties(ignoreUnknown = true)
public class SongVote implements Comparable<SongVote> {

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
	@JsonIgnoreProperties({ "votes", "comments", "playlists" })
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

	public static class OrderByIdDescComparator implements Comparator<SongVote> {

		@Override
		public int compare(SongVote o1, SongVote o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id, Ordering.natural().reverse().nullsFirst())
					.result();
		}

	}

}
