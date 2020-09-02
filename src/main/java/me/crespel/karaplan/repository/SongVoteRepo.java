package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.User;

public interface SongVoteRepo extends JpaRepository<SongVote, Long> {

	Iterable<SongVote> findAllByUser(User user);

	Optional<SongVote> findBySongAndUser(Song song, User user);

}
