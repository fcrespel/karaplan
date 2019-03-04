package me.crespel.karaplan.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import me.crespel.karaplan.domain.Playlist;

public interface PlaylistRepo extends PagingAndSortingRepository<Playlist, Long> {

}
