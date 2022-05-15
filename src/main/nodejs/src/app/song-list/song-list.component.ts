import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { Router } from '@angular/router';
import { Song } from '../models/song';
import { SongVote } from '../models/song-vote';
import { SongComment } from '../models/song-comment';
import { PlaylistSong } from '../models/playlist-song';
import { SongsService } from '../services/songs.service';
import * as Plyr from 'plyr';

@Component({
  selector: 'app-song-list',
  templateUrl: './song-list.component.html',
  styleUrls: ['./song-list.component.css']
})
export class SongListComponent implements OnInit {

  @Input() songs: PlaylistSong[] = [];
  @Input() showDuration: boolean = false;
  @Input() showVotes: boolean = true;
  @Input() showComments: boolean = true;
  @Input() showPlaylists: boolean = true;
  @Input() showRemove: boolean = false;
  @Input() allowMove: boolean = false;
  @Output() voteAdded = new EventEmitter<SongVote>();
  @Output() voteRemoved = new EventEmitter<SongVote>();
  @Output() commentAdded = new EventEmitter<SongComment>();
  @Output() commentRemoved = new EventEmitter<SongComment>();
  @Output() playlistAdded = new EventEmitter<PlaylistSong>();
  @Output() playlistRemoved = new EventEmitter<PlaylistSong>();
  @Output() songMoved = new EventEmitter<PlaylistSong[]>();
  @Output() songRemoved = new EventEmitter<Song>();

  dragging: boolean = false;
  songPlyr?: Plyr;
  songPlyrSources: Plyr.Source[] = [];
  songPlyrCurrent?: Song;

  constructor(
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
  }

  trackBySongCatalogId(index: number, playlistSong: PlaylistSong): number {
    return playlistSong.song.catalogId;
  }

  gotoSong(song: Song) {
    if (!this.dragging) {
      this.router.navigate(['/songs', song.catalogId]);
    }
  }

  moveSong(event: CdkDragDrop<PlaylistSong[]>) {
    moveItemInArray<PlaylistSong>(this.songs, event.previousIndex, event.currentIndex);
    this.songMoved.emit(this.songs);
  }

  playSong(song: Song) {
    this.stopSong();
    if (song.previewUrl) {
      this.songPlyrCurrent = song;
      this.songPlyrCurrent.previewStatus = 'waiting';
      this.songPlyrSources = [{src: song.previewUrl}];
    } else if (song.previewUrl === undefined && song.previewStatus != 'waiting') {
      this.songPlyrCurrent = song;
      this.songPlyrCurrent.previewStatus = 'waiting';
      this.songsService.getSongFiles(song.catalogId).subscribe(songFiles => {
        var songFile = songFiles.find(songFile => songFile.trackType == 'nbv-ld');
        if (songFile && songFile.previewUrl) {
          song.previewUrl = songFile.previewUrl;
          if (song == this.songPlyrCurrent) {
            this.songPlyrSources = [{src: song.previewUrl}];
          }
        } else {
          song.previewUrl = undefined;
          song.previewStatus = 'notfound';
        }
      });
    }
  }

  stopSong() {
    this.songPlyr?.stop();
    if (this.songPlyrCurrent) {
      this.songPlyrCurrent.previewStatus = 'ended';
    }
  }

  songPlyrEvent(event: Plyr.PlyrEvent) {
    var plyr = event.detail.plyr;
    var song = this.songPlyrCurrent;
    if (song && song.previewUrl == ""+plyr.source) {
      switch (event.type) {
        case 'canplay':
          if (song.previewStatus == 'waiting') {
            plyr.play();
          }
          break;
        case 'waiting':
        case 'playing':
        case 'pause':
        case 'ended':
          song.previewStatus = event.type;
          break;
      }
    }
  }

}
