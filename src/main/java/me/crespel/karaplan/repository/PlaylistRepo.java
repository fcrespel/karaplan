package me.crespel.karaplan.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistRepo extends JpaRepository<Playlist, Long> {

	List<Playlist> findAllByRestrictedOrAuthorizedUsersId(boolean restricted, Long userId);
	
	Iterable<Playlist> findAllByRestricted(boolean restricted);
}
