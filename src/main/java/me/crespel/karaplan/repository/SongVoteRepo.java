package me.crespel.karaplan.repository;

import org.springframework.data.repository.CrudRepository;

import me.crespel.karaplan.domain.SongVote;

public interface SongVoteRepo extends CrudRepository<SongVote, Long> {

}
