package me.crespel.karaplan.domain;

import java.util.Comparator;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "songs" })
@ToString(of = { "id", "name" })
@Entity
@Table(name = "style")
@JsonIgnoreProperties(ignoreUnknown = true)
public class Style implements Comparable<Style> {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@Column(name = "CATALOG_ID", unique = true)
	private Long catalogId;

	@NotNull
	@Column(name = "NAME")
	private String name;

	@Column(name = "IMAGE")
	private String image;

	@ManyToMany(mappedBy = "styles")
	private Set<Song> songs;

	@Override
	public int compareTo(Style o) {
		return orderByNameComparator.compare(this, o);
	}

	public static Comparator<Style> orderByIdComparator = new OrderByIdComparator();

	public static class OrderByIdComparator implements Comparator<Style> {

		@Override
		public int compare(Style o1, Style o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id)
					.result();
		}

	}

	public static Comparator<Style> orderByNameComparator = new OrderByNameComparator();

	public static class OrderByNameComparator implements Comparator<Style> {

		@Override
		public int compare(Style o1, Style o2) {
			return ComparisonChain.start()
					.compare(o1.name, o2.name, Ordering.natural().nullsLast())
					.compare(o1.id, o2.id, Ordering.natural().nullsLast())
					.result();
		}

	}

}
