package me.crespel.karaplan.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.User;

public interface SongVoteRepo extends CrudRepository<SongVote, Long> {

	Optional<SongVote> findBySongAndUser(Song song, User user);

}
