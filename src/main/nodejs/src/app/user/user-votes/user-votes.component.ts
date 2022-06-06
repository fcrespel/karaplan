import { Component, OnInit } from '@angular/core';
import { SongsService } from 'src/app/services/songs.service';
import { PlaylistSong } from 'src/app/models/playlist-song';

@Component({
  selector: 'app-user-votes',
  templateUrl: './user-votes.component.html',
  styleUrls: ['./user-votes.component.css']
})
export class UserVotesComponent implements OnInit {

  songs: PlaylistSong[] = [];
  songsPage: number = 0;
  songsLimit: number = 10;
  songsSort: string[] = ['score,desc', 'name,asc'];
  songsLoading: boolean = false;
  hasMoreSongs: boolean = false;
  hasMoreSongsLoading: boolean = false;

  constructor(
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.songsLoading = true;
    this.songsService.getUserSongs(0, this.songsLimit, this.songsSort).subscribe(songs => {
      this.songs = songs.map(song => { return {song: song} });
      this.songsLoading = false;
      this.hasMoreSongs = songs.length == this.songsLimit;
      this.hasMoreSongsLoading = false;
    });
  }

  loadMoreSongs() {
    if (this.hasMoreSongs) {
      this.hasMoreSongsLoading = true;
      this.songsService.getUserSongs(++this.songsPage, this.songsLimit, this.songsSort).subscribe(songs => {
        songs.forEach(song => this.songs.push({song: song}));
        this.hasMoreSongs = songs.length == this.songsLimit;
        this.hasMoreSongsLoading = false;
      });
    }
  }

}
