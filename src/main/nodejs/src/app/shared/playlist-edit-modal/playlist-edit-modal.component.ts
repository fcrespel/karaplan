import { Component, Input, inject } from '@angular/core';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Playlist } from '../../models/playlist';

@Component({
  selector: 'app-playlist-edit-modal',
  templateUrl: './playlist-edit-modal.component.html',
  styleUrls: ['./playlist-edit-modal.component.css'],
  standalone: false
})
export class PlaylistEditModalComponent {
  activeModal = inject(NgbActiveModal);

  @Input() playlist!: Playlist;

}
