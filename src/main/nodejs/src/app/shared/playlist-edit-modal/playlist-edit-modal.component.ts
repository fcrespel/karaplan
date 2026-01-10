import { Component, inject, model } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { NgbTooltip } from '@ng-bootstrap/ng-bootstrap/tooltip';
import { TranslatePipe } from '@ngx-translate/core';
import { Playlist } from '../../models/playlist';

@Component({
  selector: 'app-playlist-edit-modal',
  templateUrl: './playlist-edit-modal.component.html',
  styleUrls: ['./playlist-edit-modal.component.css'],
  imports: [FormsModule, NgbTooltip, TranslatePipe]
})
export class PlaylistEditModalComponent {
  activeModal = inject(NgbActiveModal);

  readonly playlist = model.required<Playlist>();

}
