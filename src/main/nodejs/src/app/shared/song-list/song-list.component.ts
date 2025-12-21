import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { Component, OnDestroy, inject, input, output } from '@angular/core';
import { Router } from '@angular/router';
import Plyr from 'plyr';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { PlaylistSong } from '../../models/playlist-song';
import { Song } from '../../models/song';
import { SongComment } from '../../models/song-comment';
import { SongVote } from '../../models/song-vote';
import { SongsService } from '../../services/songs.service';

@Component({
  selector: 'app-song-list',
  templateUrl: './song-list.component.html',
  styleUrls: ['./song-list.component.css'],
  standalone: false
})
export class SongListComponent implements OnDestroy {
  private router = inject(Router);
  private songsService = inject(SongsService);

  readonly songs = input<PlaylistSong[]>([]);
  readonly showDuration = input<boolean>(false);
  readonly showVotes = input<boolean>(true);
  readonly showComments = input<boolean>(true);
  readonly showPlaylists = input<boolean>(true);
  readonly showRemove = input<boolean>(false);
  readonly allowMove = input<boolean>(false);
  readonly voteAdded = output<SongVote>();
  readonly voteRemoved = output<SongVote>();
  readonly commentAdded = output<SongComment>();
  readonly commentRemoved = output<SongComment>();
  readonly playlistAdded = output<PlaylistSong>();
  readonly playlistRemoved = output<PlaylistSong>();
  readonly songMoved = output<PlaylistSong[]>();
  readonly songRemoved = output<Song>();

  dragging: boolean = false;
  songPlyr?: Plyr;
  songPlyrSources: Plyr.Source[] = [];
  songPlyrCurrent?: Song;
  destroy$: Subject<boolean> = new Subject<boolean>();

  gotoSong(song: Song) {
    if (!this.dragging) {
      this.router.navigate(['/songs', song.catalogId]);
    }
  }

  moveSong(event: CdkDragDrop<PlaylistSong[]>) {
    const songs = this.songs();
    moveItemInArray<PlaylistSong>(songs, event.previousIndex, event.currentIndex);
    this.songMoved.emit(songs);
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
      this.songsService.getSongFiles(song.catalogId)
        .pipe(takeUntil(this.destroy$))
        .subscribe(songFiles => {
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

  songPlyrEvent(event: Plyr.PlyrEvent | Plyr.PlyrStateChangeEvent) {
    const plyr = event.detail.plyr;
    const song = this.songPlyrCurrent;
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

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
