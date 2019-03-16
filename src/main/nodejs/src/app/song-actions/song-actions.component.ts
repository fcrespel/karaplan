import { Component, OnInit, Input } from '@angular/core';
import { Observable } from 'rxjs';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';
import { SongVote } from '../models/song-vote';

@Component({
  selector: 'app-song-actions',
  templateUrl: './song-actions.component.html',
  styleUrls: ['./song-actions.component.css']
})
export class SongActionsComponent implements OnInit {

  @Input() song: Song;

  constructor(
    private songsService: SongsService
  ) { }

  ngOnInit() {
  }

  voteUp($event: Event, song: Song) {
    $event.stopPropagation();
    this.songsService.voteSongByCatalogId(song.catalogId, 1).subscribe(data => {
      console.log(data);
    });
  }

  voteDown($event: Event, song: Song) {
    $event.stopPropagation();
    this.songsService.voteSongByCatalogId(song.catalogId, -1).subscribe(data => {
      console.log(data);
    });
  }

}
