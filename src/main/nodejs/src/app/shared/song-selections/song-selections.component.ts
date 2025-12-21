import { Component, input } from '@angular/core';
import { CatalogSelection } from '../../models/catalog-selection';

@Component({
  selector: 'app-song-selections',
  templateUrl: './song-selections.component.html',
  styleUrls: ['./song-selections.component.css'],
  standalone: false
})
export class SongSelectionsComponent {

  readonly selections = input<CatalogSelection[]>([]);

}
