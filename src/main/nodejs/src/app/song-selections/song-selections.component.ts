import { Component, OnInit, Input } from '@angular/core';
import { CatalogSelection } from '../models/catalog-selection';

@Component({
  selector: 'app-song-selections',
  templateUrl: './song-selections.component.html',
  styleUrls: ['./song-selections.component.css']
})
export class SongSelectionsComponent implements OnInit {

  @Input() selections: CatalogSelection[] = [];

  constructor() { }

  ngOnInit() {
  }

  trackBySelectionId(index: number, selection: CatalogSelection): number {
    return selection.id;
  }

}
