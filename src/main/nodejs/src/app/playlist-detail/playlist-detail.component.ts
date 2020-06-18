import { Component, OnInit } from '@angular/core';
import { Location } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { NgForm } from '@angular/forms';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { switchMap } from 'rxjs/operators';
import { AccountService } from '../services/account.service';
import { AlertService } from '../services/alert.service';
import { PlaylistsService } from '../services/playlists.service';
import { PlaylistEditModalComponent } from '../playlist-edit-modal/playlist-edit-modal.component';
import { PlaylistLeaveModalComponent } from '../playlist-leave-modal/playlist-leave-modal.component';
import { User } from '../models/user';
import { Playlist } from '../models/playlist';
import { Song } from '../models/song';
import { PlaylistSong } from '../models/playlist-song';
import { PlaylistComment } from '../models/playlist-comment';
import { AlertMessage } from '../models/alert-message';

@Component({
  selector: 'app-playlist-detail',
  templateUrl: './playlist-detail.component.html',
  styleUrls: ['./playlist-detail.component.css']
})
export class PlaylistDetailComponent implements OnInit {

  user: User = null;
  playlist: Playlist = null;
  playlistMembers: string;
  commentText: string;
  karafunRemoteId: string;
  karafunBarId: string;
  shareUrl: string;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private location: Location,
    private modalService: NgbModal,
    private accountService: AccountService,
    private playlistsService: PlaylistsService,
    private alertService: AlertService
  ) { }

  ngOnInit() {
    this.accountService.getUser().subscribe(user => {
      this.user = user;
    });
    this.route.paramMap.pipe(switchMap(params => {
      return this.playlistsService.getPlaylist(+params.get('id'), this.route.snapshot.queryParamMap.get('accessKey'));
    })).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  updatePlaylist(playlist?: Playlist) {
    if (playlist !== undefined) {
      this.playlist = playlist;
    }
    let urlTree = this.router.createUrlTree(['/playlists', this.playlist.id], {
      queryParams: {accessKey: this.playlist.accessKey}
    });
    this.shareUrl = window.location.origin + this.location.prepareExternalUrl(urlTree.toString());
    this.playlistMembers = this.playlist.members ? this.playlist.members.map(user => user.displayName).join(', ') : '';
  }

  joinPlaylist() {
    this.playlistsService.joinPlaylist(this.playlist.id, this.route.snapshot.queryParamMap.get('accessKey')).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  leavePlaylist() {
    let modal = this.modalService.open(PlaylistLeaveModalComponent);
    modal.componentInstance.playlist = this.playlist;
    modal.result.then((result: Playlist) => {
      this.playlistsService.leavePlaylist(result.id).subscribe(response => {
        this.router.navigate(['/playlists']);
      });
    }, reason => {});
  }

  editPlaylist() {
    let modal = this.modalService.open(PlaylistEditModalComponent);
    modal.componentInstance.playlist = new Playlist(this.playlist.id, this.playlist.name, this.playlist.readOnly);
    modal.result.then((result: Playlist) => {
      this.playlistsService.savePlaylist(result).subscribe(playlist => {
        this.updatePlaylist(playlist);
      });
    }, reason => {});
  }

  addComment(comment: string, commentForm: NgForm) {
    this.playlistsService.addCommentToPlaylist(this.playlist.id, comment).subscribe(playlist => {
      commentForm.reset();
      this.updatePlaylist(playlist);
    });
  }

  trackByCommentId(index: number, comment: PlaylistComment): number {
    return comment.id;
  }

  removeComment(comment: PlaylistComment) {
    this.playlistsService.removeCommentFromPlaylist(this.playlist.id, comment.id).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  onPlaylistRemoved(playlistSong: PlaylistSong) {
    if (playlistSong.playlist.id === this.playlist.id) {
      this.playlistsService.getPlaylist(this.playlist.id).subscribe(playlist => {
        this.updatePlaylist(playlist);
      });
    }
  }

  onSongMoved(songList: PlaylistSong[]) {
    let catalogIds: number[] = [];
    songList.forEach((song: PlaylistSong) => catalogIds.push(song.song.id));
    this.playlistsService.changeSongsOrder(this.playlist.id, catalogIds).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  onSongRemoved(song: Song) {
    this.playlistsService.removeSongFromPlaylist(this.playlist.id, song.catalogId).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  sortPlaylist(sortType: string, sortDirection: string) {
    this.playlistsService.sortPlaylist(this.playlist.id, sortType, sortDirection).subscribe(playlist => {
      this.updatePlaylist(playlist);
    });
  }

  exportPlaylistToKarafunRemote(modalContent) {
    this.modalService.open(modalContent).result.then(remoteId => {
      if (remoteId) {
        this.playlistsService.exportPlaylistToKarafunRemote(this.playlist.id, remoteId).subscribe(response => {
          let message = new AlertMessage();
          message.severity = 'success';
          message.title = 'Success';
          message.text = `Export to KaraFun Remote #${remoteId} completed successfully`;
          this.alertService.addMessage(message);
        });
      }
    }, reason => {});
  }

  exportPlaylistToKarafunBar(modalContent) {
    this.modalService.open(modalContent).result.then(bookingId => {
      if (bookingId) {
        this.playlistsService.exportPlaylistToKarafunBar(this.playlist.id, bookingId).subscribe(response => {
          let message = new AlertMessage();
          message.severity = 'success';
          message.title = 'Success';
          message.text = `Export to KaraFun Bar session #${bookingId} completed successfully`;
          this.alertService.addMessage(message);
        });
      }
    }, reason => {});
  }

  copyToClipboard(field: HTMLInputElement) {
    field.focus();
    field.select();
    document.execCommand('copy');
  }

  isMember(user: User, playlist: Playlist) {
    return user && playlist && playlist.members && playlist.members.findIndex(member => member.id == user.id) >= 0;
  }

}
