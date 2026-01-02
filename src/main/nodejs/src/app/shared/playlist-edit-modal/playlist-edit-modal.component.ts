import { Component, inject, model } from '@angular/core';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Playlist } from '../../models/playlist';
import { FormsModule } from '@angular/forms';
import { NgbTooltip } from '@ng-bootstrap/ng-bootstrap/tooltip';

@Component({
  selector: 'app-playlist-edit-modal',
  templateUrl: './playlist-edit-modal.component.html',
  styleUrls: ['./playlist-edit-modal.component.css'],
  imports: [FormsModule, NgbTooltip]
})
export class PlaylistEditModalComponent {
  activeModal = inject(NgbActiveModal);

  readonly playlist = model.required<Playlist>();

}
