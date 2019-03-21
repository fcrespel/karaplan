package me.crespel.karaplan.domain;

import java.util.SortedSet;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.SortComparator;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = {"votes", "comments"})
@ToString(of = {"id", "username"})
@Entity
@Table(name = "user")
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "USERNAME", unique = true)
	private String username;

	@NotNull
	@Column(name = "DISPLAYNAME")
	private String displayName;

	@Column(name = "FIRSTNAME")
	private String firstName;

	@Column(name = "LASTNAME")
	private String lastName;

	@Column(name = "FULLNAME")
	private String fullName;

	@Column(name = "EMAIL")
	private String email;

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	@SortComparator(SongVote.OrderByIdDescComparator.class)
	@OrderBy("id DESC")
	private SortedSet<SongVote> votes = Sets.newTreeSet(SongVote.orderByIdDescComparator);

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	@SortComparator(SongComment.OrderByIdDescComparator.class)
	@OrderBy("id DESC")
	private SortedSet<SongComment> comments = Sets.newTreeSet(SongComment.orderByIdDescComparator);

}
