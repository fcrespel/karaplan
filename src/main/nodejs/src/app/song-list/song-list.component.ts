import { Component, OnInit, Input, Output, EventEmitter, ViewChild, SimpleChanges, IterableDiffer, IterableDiffers, IterableChanges } from '@angular/core';
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { Router } from '@angular/router';
import { Song } from '../models/song';
import { SongVote } from '../models/song-vote';
import { SongComment } from '../models/song-comment';
import { PlaylistSong } from '../models/playlist-song';
import { SongsService } from '../services/songs.service';
import { CatalogSongFile } from '../models/catalog-song-file';
import { PlyrComponent } from 'ngx-plyr';

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
  @Input() allowMove: boolean = false;
  @Output() voteAdded = new EventEmitter<SongVote>();
  @Output() voteRemoved = new EventEmitter<SongVote>();
  @Output() commentAdded = new EventEmitter<SongComment>();
  @Output() commentRemoved = new EventEmitter<SongComment>();
  @Output() playlistAdded = new EventEmitter<PlaylistSong>();
  @Output() playlistRemoved = new EventEmitter<PlaylistSong>();
  @Output() songMoved = new EventEmitter<Song[] | PlaylistSong[]>();
  @Output() songRemoved = new EventEmitter<Song>();

  dragging: boolean;

  @ViewChild(PlyrComponent, {static: false}) plyr: PlyrComponent;
  player: Plyr;
  preview: CatalogSongFile;
  _diff: IterableDiffer<Song | PlaylistSong>;

  constructor(
    private router: Router,
    private songsService: SongsService,
    private _iterableDiffers: IterableDiffers
  ) { }

  ngOnInit() {
  }

  ngOnChanges(changes: SimpleChanges) {
    this._diff = this._iterableDiffers.find(this.songs).create();
    this.songs.forEach((song: Song | PlaylistSong) => {
      this.setPreview(song);
    });
  }

  ngDoCheck() {
    const changes: IterableChanges<Song | PlaylistSong> = this._diff.diff(this.songs);

    if(changes) {
      this.songs.forEach((song: Song | PlaylistSong) => {
        this.setPreview(song);
      });
    }
  }

  trackBySongCatalogId(index: number, song: Song | PlaylistSong): number {
    if ('song' in song) {
      return song.song.catalogId;
    } else {
      return song.catalogId;
    }
  }

  gotoSong(song: Song | PlaylistSong) {
    if (!this.dragging) {
      if ('song' in song) {
        this.router.navigate(['/songs', song.song.catalogId]);
      } else {
        this.router.navigate(['/songs', song.catalogId]);
      }
    }
  }

  moveSong(event: CdkDragDrop<Song[] | PlaylistSong[]>) {
    moveItemInArray<Song | PlaylistSong>(this.songs, event.previousIndex, event.currentIndex);
    this.songMoved.emit(this.songs);
  }

  setPreview(song: Song | PlaylistSong): void {
    const catalogId = this.trackBySongCatalogId(null, song);
    this.songsService.getSongFiles(catalogId).subscribe(songFiles => {
      songFiles.forEach((file: CatalogSongFile) => {
        if (file.trackType == 'nbv-ld') {
          if ('song' in song) {
            song.song.previewUrl = file.previewUrl;
          } else {
            song.previewUrl = file.previewUrl;
          }
        }
      });
    });
  }

  play() {
    this.player.play();
  }

}
