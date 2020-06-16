package me.crespel.karaplan.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.User;

public interface SongVoteRepo extends JpaRepository<SongVote, Long> {

	Optional<SongVote> findBySongAndUser(Song song, User user);
	
	List<SongVote> findByUser(User user);
	
	@Modifying
	@Query("delete from SongVote sv where sv.user.id = :id")
	void deleteByUserId(Long id);

}
