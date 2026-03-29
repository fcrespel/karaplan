package me.crespel.karaplan.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.Locale;
import java.util.SortedSet;

import org.hibernate.annotations.SortComparator;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Sets;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
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
public class User implements Serializable {

	private static final long serialVersionUID = 1L;

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
	@Column(name = "CREATED_DATE")
	private Instant createdDate;

	@LastModifiedDate
	@Column(name = "UPDATED_DATE")
	private Instant updatedDate;

	private transient Locale localeParsed = null;

	@JsonIgnore
	public Locale getLocaleParsed() {
		if (locale != null) {
			localeParsed = Locale.forLanguageTag(locale);
		}
		if (locale == null) {
			localeParsed = LocaleContextHolder.getLocale();
		}
		return localeParsed;
	}

	public User setLocale(String locale) {
		this.locale = locale;
		this.localeParsed = null;
		return this;
	}

}
