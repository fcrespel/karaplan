import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Router } from '@angular/router';
import { Song } from '../models/song';
import { SongVote } from '../models/song-vote';
import { SongComment } from '../models/song-comment';
import { PlaylistSong } from '../models/playlist-song';
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';

@Component({
  selector: 'app-song-list',
  templateUrl: './song-list.component.html',
  styleUrls: ['./song-list.component.css']
})
export class SongListComponent implements OnInit {

  @Input() songs: Song[] | PlaylistSong[];
  @Input() showDuration: boolean = false;
  @Input() showVotes: boolean = true;
  @Input() showComments: boolean = true;
  @Input() showPlaylists: boolean = true;
  @Input() showRemove: boolean = false;
  @Output() voteAdded = new EventEmitter<SongVote>();
  @Output() voteRemoved = new EventEmitter<SongVote>();
  @Output() commentAdded = new EventEmitter<SongComment>();
  @Output() commentRemoved = new EventEmitter<SongComment>();
  @Output() playlistAdded = new EventEmitter<PlaylistSong>();
  @Output() playlistRemoved = new EventEmitter<PlaylistSong>();
  @Output() songMoved = new EventEmitter<Song[] | PlaylistSong[]>();
  @Output() songRemoved = new EventEmitter<Song>();

  dragging: boolean;
  activeIndex: number;
  previousIndex: number;

  constructor(
    private router: Router
  ) { }

  ngOnInit() {
  }

  trackBySongCatalogId(index: number, song: Song | PlaylistSong): number {
    if ('song' in song) {
      return song.song.catalogId;
    } else {
      return song.catalogId;
    }
  }

  gotoSong(song: Song | PlaylistSong) {
    if(!this.dragging) {
      if ('song' in song) {
        this.router.navigate(['/songs', song.song.catalogId]);
      } else {
        this.router.navigate(['/songs', song.catalogId]);
      }
    }
  }

  enter(i) {
    this.activeIndex = i;
  }
  moveSong(event: CdkDragDrop<Song[] | PlaylistSong[]>) {
    moveItemInArray<Song | PlaylistSong>(this.songs, this.previousIndex, this.activeIndex);
    this.songMoved.emit(this.songs);
  }

}
