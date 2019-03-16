import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { Observable, empty } from 'rxjs';
import { NgbTabChangeEvent } from '@ng-bootstrap/ng-bootstrap';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';
import { CatalogSelection } from '../models/catalog-selection';

@Component({
  selector: 'app-songs',
  templateUrl: './songs.component.html',
  styleUrls: ['./songs.component.css']
})
export class SongsComponent implements OnInit {

  type: string;
  query: string;
  songs$: Observable<Song[]>;
  selections$: Observable<CatalogSelection[]>;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.route.queryParamMap.subscribe(params => {
      this.type = params.get('type') || 'query';
      this.query = params.get('query') || '';
      if (this.type == 'query' || this.query) {
        this.songs$ = this.songsService.search(this.type, this.query);
        this.selections$ = empty();
      } else {
        this.songs$ = empty();
        this.selections$ = this.songsService.getSelections(this.type);
      }
    });
  }

  onSearch(query: string) {
    this.router.navigate(['/songs'], { queryParams: { query: query } });
  }

  onTabChange($event: NgbTabChangeEvent) {
    this.router.navigate(['/songs'], { queryParams: { type: $event.nextId } });
  }

}
