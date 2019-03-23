import { Component, OnInit, Input } from '@angular/core';
import { Router } from '@angular/router';
import { Song } from '../models/song';

@Component({
  selector: 'app-song-list',
  templateUrl: './song-list.component.html',
  styleUrls: ['./song-list.component.css']
})
export class SongListComponent implements OnInit {

  @Input() songs: Song[];
  @Input() showDuration: boolean = false;
  @Input() showVotes: boolean = true;
  @Input() showComments: boolean = true;
  @Input() showPlaylists: boolean = true;
  @Input() showRemove: boolean = false;

  constructor(
    private router: Router
  ) { }

  ngOnInit() {
  }

  trackBySongId(index: number, song: Song): number {
    return song.id;
  }

  gotoSong(song: Song) {
    this.router.navigate(['/songs', song.catalogId]);
  }

}
