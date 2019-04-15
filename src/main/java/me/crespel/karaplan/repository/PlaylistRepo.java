package me.crespel.karaplan.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistRepo extends JpaRepository<Playlist, Long> {

	Page<Playlist> findAllByRestrictedOrMembersId(boolean restricted, Long userId, Pageable pageable);

}
