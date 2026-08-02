import { Component, input, ChangeDetectionStrategy } from '@angular/core';
import { CatalogSelection } from '../../models/catalog-selection';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-song-selections',
  templateUrl: './song-selections.component.html',
  styleUrls: ['./song-selections.component.css'],
  changeDetection: ChangeDetectionStrategy.Eager,
  imports: [RouterLink]
})
export class SongSelectionsComponent {

  readonly selections = input<CatalogSelection[]>([]);

}
