package me.crespel.karaplan.domain;

import java.util.Calendar;
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
import com.google.common.collect.Sets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(exclude = { "votes", "comments", "createdDate", "updatedDate" })
@ToString(of = { "id", "username", "displayName" })
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "user")
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {

	@Id
	@GeneratedValue
	@Column(name = "ID", unique = true)
	private Long id;

	@NotNull
	@Column(name = "PROVIDER")
	private String provider;

	@NotNull
	@Column(name = "USERNAME")
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

	@Column(name = "LOCALE")
	private String locale;

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	@SortComparator(SongVote.OrderByIdDescComparator.class)
	private SortedSet<SongVote> votes = Sets.newTreeSet(SongVote.orderByIdDescComparator);

	@OneToMany(mappedBy = "user")
	@JsonIgnoreProperties("user")
	@SortComparator(SongComment.OrderByIdDescComparator.class)
	private SortedSet<SongComment> comments = Sets.newTreeSet(SongComment.orderByIdDescComparator);

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "CREATED_DATE")
	private Calendar createdDate;

	@LastModifiedDate
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "UPDATED_DATE")
	private Calendar updatedDate;

}
