import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { SongsService } from '../services/songs.service';
import { Song } from '../models/song';
import { CatalogSelection } from '../models/catalog-selection';
import { switchMap, map } from 'rxjs/operators';
import { of, concat } from 'rxjs';

@Component({
  selector: 'app-songs',
  templateUrl: './songs.component.html',
  styleUrls: ['./songs.component.css']
})
export class SongsComponent implements OnInit {

  queryContext: QueryContext = new QueryContext();

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songsService: SongsService
  ) { }

  ngOnInit() {
    this.route.queryParamMap.pipe(switchMap(params => {
      let type = params.get('type') || 'query';
      let query = params.get('query') || '';
      if (type == 'query' || query) {
        return concat(of(new QueryContext(type, query, true)), this.songsService.searchSongs(type, query).pipe(map(songs => {
          let result = new QueryContext(type, query);
          result.songs = songs;
          result.hasMoreSongs = songs && songs.length == result.songsLimit;
          return result;
        })));
      } else {
        return concat(of(new QueryContext(type, query, true)), this.songsService.getSelections(type).pipe(map(selections => {
          let result = new QueryContext(type, query);
          result.selections = selections;
          return result;
        })));
      }
    })).subscribe(result => {
      this.queryContext = result;
    });
  }

  onSearch(query: string) {
    this.router.navigate(['/songs'], { queryParams: { query: query } });
  }

  loadMoreSongs() {
    let queryContext = this.queryContext;
    if (queryContext.hasMoreSongs && (queryContext.type == 'query' || queryContext.query)) {
      queryContext.hasMoreSongsLoading = true;
      this.songsService.searchSongs(queryContext.type, queryContext.query, ++queryContext.songsPage).subscribe(songs => {
        songs.forEach(song => queryContext.songs.push(song));
        queryContext.hasMoreSongs = songs.length == queryContext.songsLimit;
        queryContext.hasMoreSongsLoading = false;
      });
    }
  }

}

class QueryContext {
  songs: Song[] = [];
  songsPage: number = 0;
  songsLimit: number = 10;
  hasMoreSongs: boolean = false;
  hasMoreSongsLoading: boolean = false;
  selections: CatalogSelection[];

  constructor(
    public type: string = 'query',
    public query: string = '',
    public loading: boolean = false
  ) { }
}
