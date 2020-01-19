package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.util.Comparator;
import java.util.Set;

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
@JsonIgnoreProperties(ignoreUnknown = true)
public class Style implements Comparable<Style>, Serializable {

	private static final long serialVersionUID = 1L;

	private Long id;
	private Long catalogId;
	private String name;
	private String image;
	private Set<Song> songs;

	@Override
	public int compareTo(Style o) {
		return orderByNameComparator.compare(this, o);
	}

	public static Comparator<Style> orderByIdComparator = new OrderByIdComparator();

	public static class OrderByIdComparator implements Comparator<Style>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Style o1, Style o2) {
			return ComparisonChain.start()
					.compare(o1.id, o2.id)
					.result();
		}

	}

	public static Comparator<Style> orderByNameComparator = new OrderByNameComparator();

	public static class OrderByNameComparator implements Comparator<Style>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(Style o1, Style o2) {
			return ComparisonChain.start()
					.compare(o1.name, o2.name, Ordering.natural().nullsLast())
					.compare(o1.id, o2.id, Ordering.natural().nullsLast())
					.result();
		}

	}

}
