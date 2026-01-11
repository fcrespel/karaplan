import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { ActivatedRoute, ParamMap, RouterLink } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';
import * as Plyr from 'plyr';
import { Subject, of } from 'rxjs';
import { catchError, switchMap, takeUntil } from 'rxjs/operators';
import { CatalogSongFile } from '../../models/catalog-song-file';
import { PlaylistSong } from '../../models/playlist-song';
import { Song } from '../../models/song';
import { SongComment } from '../../models/song-comment';
import { SongLyrics } from '../../models/song-lyrics';
import { User } from '../../models/user';
import { AccountService } from '../../services/account.service';
import { SongsService } from '../../services/songs.service';
import { DurationPipe } from '../../shared/pipes/duration.pipe';
import { PlyrComponent } from '../../shared/plyr/plyr.component';
import { SongActionsComponent } from '../../shared/song-actions/song-actions.component';
import { SongListComponent } from '../../shared/song-list/song-list.component';

@Component({
  selector: 'app-song-detail',
  templateUrl: './song-detail.component.html',
  styleUrls: ['./song-detail.component.css'],
  imports: [RouterLink, SongActionsComponent, PlyrComponent, FormsModule, SongListComponent, DurationPipe, TranslatePipe]
})
export class SongDetailComponent implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private accountService = inject(AccountService);
  private songsService = inject(SongsService);

  user?: User;
  song?: Song;
  songLyrics?: SongLyrics;
  songFiles: CatalogSongFile[] = [];
  relatedSongs: PlaylistSong[] = [];
  relatedSongsPage: number = 0;
  relatedSongsLimit: number = 10;
  hasMoreRelatedSongs: boolean = false;
  tab: string = 'info';
  commentText: string = '';
  preview?: CatalogSongFile;
  songFilePlyr?: Plyr;
  songFilePlyrSources: Plyr.Source[] = [];
  songFilePlyrCurrent?: CatalogSongFile;
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.accountService.getUser()
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => this.user = user);
    this.route.paramMap
      .pipe(takeUntil(this.destroy$))
      .pipe(switchMap((params: ParamMap) => 
        this.songsService.getSong(+params.get('catalogId')!).pipe(catchError(err => of({} as Song)))
      ))
      .subscribe(song => {
        this.relatedSongsPage = 0;
        this.hasMoreRelatedSongs = false;
        this.song = song;
        this.songLyrics = undefined;
        this.songFiles = [];
        this.preview = undefined;
        this.relatedSongs = [];
        this.hasMoreRelatedSongs = false;
        if (song?.catalogId) {
          this.switchTab('info');
          this.songsService.getSongLyrics(song.catalogId)
            .pipe(takeUntil(this.destroy$))
            .subscribe(songLyrics => this.songLyrics = songLyrics);
          this.songsService.getSongFiles(song.catalogId)
            .pipe(takeUntil(this.destroy$))
            .subscribe(songFiles => {
              this.songFiles = songFiles;
              this.preview = songFiles.find(songFile => songFile.format == 'wmv' || songFile.format == 'mp4') || songFiles.find(songFile => songFile.trackType == 'nbv-ld');
            });
          this.songsService.searchSongs('artist', ''+song.artist.catalogId, 0, this.relatedSongsLimit)
            .pipe(takeUntil(this.destroy$))
            .subscribe(songs => {
              this.relatedSongs = songs.filter(song => song.catalogId != this.song?.catalogId).map(song => { return {song: song} });
              this.hasMoreRelatedSongs = songs.length == this.relatedSongsLimit;
            });
        } else {
          this.switchTab('error');
        }
      });
  }

  switchTab(tab: string) {
    this.tab = tab;
    this.stopSongFile();
  }

  addComment(comment: string, commentForm: NgForm) {
    this.songsService.addCommentToSong(this.song!.catalogId, comment)
      .pipe(takeUntil(this.destroy$))
      .subscribe(song => {
        commentForm.reset();
        this.song = song;
      });
  }

  removeComment(comment: SongComment) {
    this.songsService.removeCommentFromSong(this.song!.catalogId, comment.id)
      .pipe(takeUntil(this.destroy$))
      .subscribe(song => this.song = song);
  }

  loadMoreRelatedSongs() {
    if (this.hasMoreRelatedSongs) {
      this.songsService.searchSongs('artist', ''+this.song!.artist.catalogId, ++this.relatedSongsPage, this.relatedSongsLimit)
        .pipe(takeUntil(this.destroy$))
        .subscribe(songs => {
          songs.filter(song => song.catalogId != this.song!.catalogId).forEach(song => this.relatedSongs.push({song: song}));
          this.hasMoreRelatedSongs = songs.length == this.relatedSongsLimit;
        });
    }
  }

  playSongFile(songFile: CatalogSongFile) {
    this.stopSongFile();
    if (songFile.previewUrl) {
      this.songFilePlyrCurrent = songFile;
      this.songFilePlyrCurrent.previewStatus = 'waiting';
      this.songFilePlyrSources = [{src: songFile.previewUrl}];
    }
  }

  stopSongFile() {
    this.songFilePlyr?.stop();
    if (this.songFilePlyrCurrent) {
      this.songFilePlyrCurrent.previewStatus = 'ended';
    }
  }

  songFilePlyrEvent(event: Plyr.PlyrEvent | Plyr.PlyrStateChangeEvent) {
    var plyr = event.detail.plyr;
    var songFile = this.songFilePlyrCurrent;
    if (songFile && songFile.previewUrl == ""+plyr.source) {
      switch (event.type) {
        case 'canplay':
          if (songFile.previewStatus == 'waiting') {
            plyr.play();
          }
          break;
        case 'waiting':
        case 'playing':
        case 'pause':
        case 'ended':
          songFile.previewStatus = event.type;
          break;
      }
    }
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
