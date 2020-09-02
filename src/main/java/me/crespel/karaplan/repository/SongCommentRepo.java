package me.crespel.karaplan.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.User;

public interface SongCommentRepo extends JpaRepository<SongComment, Long> {

	Iterable<SongComment> findAllByUser(User user);

}
