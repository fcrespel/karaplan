import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { NgForm } from '@angular/forms';
import { ActivatedRoute, ParamMap } from '@angular/router';
import Plyr from 'plyr';
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

@Component({
  selector: 'app-song-detail',
  templateUrl: './song-detail.component.html',
  styleUrls: ['./song-detail.component.css'],
  standalone: false
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

  trackTypeLabels: any = {
    'nbv': 'Instrumental',
    'nbv-gm': 'Instrumental + backing vocals',
    'nbv-ld': 'Cover version',
    'wmv': 'Karaoke video',
    'mp4': 'Karaoke video',
    'cdg': 'Karaoke CDG file',
    'kfn': 'KaraFun format',
    'ngt': 'No guitar',
    'ngt-voc': 'No guitar + vocals',
    'ngt-gt-voc': 'Guitar + vocals',
    'gt': 'Guitar only',
    'ndr': 'No drums',
    'ndr-voc': 'No drums + vocals',
    'ndr-dr-voc': 'Drums + vocals',
    'dr': 'Drums only',
    'nba': 'No bass',
    'nba-voc': 'No bass + vocals',
    'nba-ba-voc': 'Bass + vocals',
    'ba': 'Bass only',
    'npi': 'No piano',
    'npi-voc': 'No piano + vocals',
    'npi-pi-voc': 'Piano + vocals',
    'pi': 'Piano only',
  };

  ngOnInit() {
    this.accountService.getUser()
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => this.user = user);
    this.route.paramMap
      .pipe(takeUntil(this.destroy$))
      .pipe(switchMap((params: ParamMap) => 
        this.songsService.getSong(+params.get('catalogId')!).pipe(catchError(err => of(undefined)))
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

  getSongFileTrackTypeLabel(songFile: CatalogSongFile): string {
    if (songFile.trackType in this.trackTypeLabels) {
      return this.trackTypeLabels[songFile.trackType];
    } else {
      return 'Unknown';
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
