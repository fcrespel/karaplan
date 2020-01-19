package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Comparator;
import java.util.SortedSet;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.SortComparator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "songs", "createdDate", "updatedDate" })
@ToString(of = { "id", "name" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "artist")
@JsonIgnoreProperties(ignoreUnknown = true)
public class Artist implements Comparable<Artist>, Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@Column(name = "CATALOG_ID", unique = true)
	private Long catalogId;

	@NotNull
	@Column(name = "NAME")
	private String name;

	@OneToMany(mappedBy = "artist")
	@JsonIgnoreProperties("artist")
	@SortComparator(Song.OrderByNameComparator.class)
	private SortedSet<Song> songs = Sets.newTreeSet(Song.orderByNameComparator);

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "CREATED_DATE")
	private Calendar createdDate;

	@LastModifiedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "UPDATED_DATE")
	private Calendar updatedDate;

	@Override
	public int compareTo(Artist o) {
		return orderByNameComparator.compare(this, o);
	}

	public static Comparator<Artist> orderByIdComparator = new OrderByIdComparator();

	public static class OrderByIdComparator implements Comparator<Artist>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Artist o1, Artist o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id)
					.result();
		}

	}

	public static Comparator<Artist> orderByNameComparator = new OrderByNameComparator();

	public static class OrderByNameComparator implements Comparator<Artist>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Artist o1, Artist o2) {
			return ComparisonChain.start()
					.compare(o1.name, o2.name, Ordering.natural().nullsLast())
					.compare(o1.id, o2.id, Ordering.natural().nullsLast())
					.result();
		}

	}

}
