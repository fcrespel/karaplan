import { Component, OnInit, Input, inject } from '@angular/core';
import { Location } from '@angular/common';
import { Router } from '@angular/router';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Playlist } from '../../models/playlist';

@Component({
  selector: 'app-playlist-leave-modal',
  templateUrl: './playlist-leave-modal.component.html',
  styleUrls: ['./playlist-leave-modal.component.css'],
  standalone: false
})
export class PlaylistLeaveModalComponent implements OnInit {
  activeModal = inject(NgbActiveModal);
  private router = inject(Router);
  private location = inject(Location);

  @Input() playlist!: Playlist;
  shareUrl: string = '';

  ngOnInit() {
    let urlTree = this.router.createUrlTree(['/playlists', this.playlist.id], {
      queryParams: {accessKey: this.playlist.accessKey}
    });
    this.shareUrl = window.location.origin + this.location.prepareExternalUrl(urlTree.toString());
  }

  copyToClipboard(field: HTMLInputElement) {
    field.focus();
    field.select();
    document.execCommand('copy');
  }

}
