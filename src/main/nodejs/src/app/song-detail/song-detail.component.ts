import { Component, OnInit, ViewChild } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { NgForm } from '@angular/forms';
import { of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';
import { AccountService } from '../services/account.service';
import { SongsService } from '../services/songs.service';
import { User } from '../models/user';
import { Song } from '../models/song';
import { SongComment } from '../models/song-comment';
import { CatalogSongFile } from '../models/catalog-song-file';
import { PlyrComponent } from 'ngx-plyr';

@Component({
  selector: 'app-song-detail',
  templateUrl: './song-detail.component.html',
  styleUrls: ['./song-detail.component.css']
})
export class SongDetailComponent implements OnInit {

  @ViewChild(PlyrComponent, {static: false}) plyr: PlyrComponent;
  player: Plyr;

  user: User = null;
  song: Song = null;
  songFiles: CatalogSongFile[] = [];
  relatedSongs: Song[] = [];
  relatedSongsPage: number = 0;
  relatedSongsLimit: number = 10;
  hasMoreRelatedSongs: boolean = false;
  tab: string = 'info';
  commentText: string;
  preview: CatalogSongFile;

  trackTypeLabels = {
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
  }

  constructor(
    private route: ActivatedRoute,
    private accountService: AccountService,
    private songsService: SongsService
  ) { }
   
  play(): void {
    this.player.play();
  }

  ngOnInit() {
    this.accountService.getUser().subscribe(user => {
      this.user = user;
    });
    this.route.paramMap.pipe(
      switchMap((params: ParamMap) => 
        this.songsService.getSong(+params.get('catalogId')).pipe(catchError(err => of(new Song())))
      )
    ).subscribe(song => {
      this.relatedSongsPage = 0;
      this.hasMoreRelatedSongs = false;
      this.song = song;
      if (song.catalogId) {
        this.tab = 'info';
        this.songsService.getSongFiles(song.catalogId).subscribe(songFiles => {
          this.songFiles = songFiles;
          this.songFiles.forEach((file: CatalogSongFile) => {
            if (file.format == 'wmv' || file.format == 'mp4') {
              this.preview = file;
            }
          });
        });
        this.songsService.searchSongs('artist', ''+song.artist.catalogId).subscribe(songs => {
          this.relatedSongs = songs.filter(song => song.catalogId != this.song.catalogId);
          this.hasMoreRelatedSongs = songs.length == this.relatedSongsLimit;
        });
      } else {
        this.tab = 'error';
      }
    });
  }

  switchTab($event: Event, tab: string) {
    $event.preventDefault();
    this.tab = tab;
  }

  trackByCommentId(index: number, comment: SongComment): number {
    return comment.id;
  }

  trackBySongFileId(index: number, songFile: CatalogSongFile): number {
    return songFile.id;
  }

  addComment(comment: string, commentForm: NgForm) {
    this.songsService.addCommentToSong(this.song.catalogId, comment).subscribe(song => {
      commentForm.reset();
      this.song = song;
    });
  }

  removeComment(comment: SongComment) {
    this.songsService.removeCommentFromSong(this.song.catalogId, comment.id).subscribe(song => {
      this.song = song;
    });
  }

  loadMoreRelatedSongs() {
    if (this.hasMoreRelatedSongs) {
      this.songsService.searchSongs('artist', ''+this.song.artist.catalogId, ++this.relatedSongsPage).subscribe(songs => {
        songs.filter(song => song.catalogId != this.song.catalogId).forEach(song => this.relatedSongs.push(song));
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

}
