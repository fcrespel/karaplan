import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { NgForm } from '@angular/forms';
import { of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';
import { AccountService } from '../../services/account.service';
import { SongsService } from '../../services/songs.service';
import { User } from '../../models/user';
import { Song } from '../../models/song';
import { SongLyrics } from '../../models/song-lyrics';
import { SongComment } from '../../models/song-comment';
import { PlaylistSong } from '../../models/playlist-song';
import { CatalogSongFile } from '../../models/catalog-song-file';
import * as Plyr from 'plyr';

@Component({
  selector: 'app-song-detail',
  templateUrl: './song-detail.component.html',
  styleUrls: ['./song-detail.component.css']
})
export class SongDetailComponent implements OnInit {

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

  constructor(
    private route: ActivatedRoute,
    private accountService: AccountService,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.accountService.getUser().subscribe(user => {
      this.user = user;
    });
    this.route.paramMap.pipe(
      switchMap((params: ParamMap) => 
        this.songsService.getSong(+params.get('catalogId')!).pipe(catchError(err => of(undefined)))
      )
    ).subscribe(song => {
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
        this.songsService.getSongLyrics(song.catalogId).subscribe(songLyrics => {
          this.songLyrics = songLyrics;
        });
        this.songsService.getSongFiles(song.catalogId).subscribe(songFiles => {
          this.songFiles = songFiles;
          this.preview = songFiles.find(songFile => songFile.format == 'wmv' || songFile.format == 'mp4') || songFiles.find(songFile => songFile.trackType == 'nbv-ld');
        });
        this.songsService.searchSongs('artist', ''+song.artist.catalogId, 0, this.relatedSongsLimit).subscribe(songs => {
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

  trackByCommentId(index: number, comment: SongComment): number {
    return comment.id;
  }

  trackBySongFileId(index: number, songFile: CatalogSongFile): number {
    return songFile.id;
  }

  addComment(comment: string, commentForm: NgForm) {
    this.songsService.addCommentToSong(this.song!.catalogId, comment).subscribe(song => {
      commentForm.reset();
      this.song = song;
    });
  }

  removeComment(comment: SongComment) {
    this.songsService.removeCommentFromSong(this.song!.catalogId, comment.id).subscribe(song => {
      this.song = song;
    });
  }

  loadMoreRelatedSongs() {
    if (this.hasMoreRelatedSongs) {
      this.songsService.searchSongs('artist', ''+this.song!.artist.catalogId, ++this.relatedSongsPage, this.relatedSongsLimit).subscribe(songs => {
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

  songFilePlyrEvent(event: Plyr.PlyrEvent) {
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

}
