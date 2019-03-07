package me.crespel.karaplan.repository;

import org.springframework.data.repository.CrudRepository;

import me.crespel.karaplan.domain.SongComment;

public interface SongCommentRepo extends CrudRepository<SongComment, Long> {

}
