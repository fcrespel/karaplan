package me.crespel.karaplan.domain;

import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Data
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

	@Column(name = "FIRSTNAME")
	private String firstName;

	@Column(name = "LASTNAME")
	private String lastName;

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	private Set<SongVote> votes = Sets.newLinkedHashSet();

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	private Set<SongComment> comments = Sets.newLinkedHashSet();

}
