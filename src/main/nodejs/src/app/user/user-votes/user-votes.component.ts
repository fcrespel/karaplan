import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { PlaylistSong } from '../../models/playlist-song';
import { SongsService } from '../../services/songs.service';

@Component({
  selector: 'app-user-votes',
  templateUrl: './user-votes.component.html',
  styleUrls: ['./user-votes.component.css'],
  standalone: false
})
export class UserVotesComponent implements OnInit, OnDestroy {

  songs: PlaylistSong[] = [];
  songsPage: number = 0;
  songsLimit: number = 10;
  songsSort: string[] = ['score,desc', 'name,asc'];
  songsLoading: boolean = false;
  hasMoreSongs: boolean = false;
  hasMoreSongsLoading: boolean = false;
  destroy$: Subject<boolean> = new Subject<boolean>();

  constructor(
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.songsLoading = true;
    this.songsService.getUserSongs(0, this.songsLimit, this.songsSort)
      .pipe(takeUntil(this.destroy$))
      .subscribe(songs => {
        this.songs = songs.map(song => { return {song: song} });
        this.songsLoading = false;
        this.hasMoreSongs = songs.length == this.songsLimit;
        this.hasMoreSongsLoading = false;
      });
  }

  loadMoreSongs() {
    if (this.hasMoreSongs) {
      this.hasMoreSongsLoading = true;
      this.songsService.getUserSongs(++this.songsPage, this.songsLimit, this.songsSort)
        .pipe(takeUntil(this.destroy$))
        .subscribe(songs => {
          songs.forEach(song => this.songs.push({song: song}));
          this.hasMoreSongs = songs.length == this.songsLimit;
          this.hasMoreSongsLoading = false;
        });
    }
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
