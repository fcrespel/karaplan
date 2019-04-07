package me.crespel.karaplan.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistRepo extends JpaRepository<Playlist, Long> {

	Iterable<Playlist> findAllByRestricted(boolean restricted);

	Iterable<Playlist> findAllByRestrictedOrAuthorizedUsersId(boolean restricted, Long userId);

}
