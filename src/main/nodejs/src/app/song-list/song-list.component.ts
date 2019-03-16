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

  constructor(
    private router: Router
  ) { }

  ngOnInit() {
  }

  gotoSong(song: Song) {
    this.router.navigate(['/songs', song.catalogId]);
  }

}
