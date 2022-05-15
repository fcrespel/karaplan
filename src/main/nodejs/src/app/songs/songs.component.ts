import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { SongsService } from '../services/songs.service';
import { PlaylistSong } from '../models/playlist-song';
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
  queryField: string = '';

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
        return concat(of(new QueryContext(type, query, true)), this.songsService.searchSongs(type, query, 0, this.queryContext.songsLimit).pipe(map(songs => {
          let result = new QueryContext(type, query);
          result.songs = songs.map(song => { return {song: song} });
          result.hasMoreSongs = songs && songs.length == result.songsLimit;
          if (type != 'query') {
            this.songsService.getSelection(type, +query).subscribe(selection => result.selection = selection);
          }
          return result;
        })));
      } else if (type == 'votes') {
        return concat(of(new QueryContext(type, query, true)), this.songsService.getSongs(0, this.queryContext.songsLimit, 'score,desc').pipe(map(songs => {
          let result = new QueryContext(type, query);
          result.songs = songs.map(song => { return {song: song} });
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
      if (result.loading) {
        this.queryField = result.query;
      }
    });
  }

  onSearch(query: string) {
    this.router.navigate(['/songs'], { queryParams: { query: query } });
  }

  loadMoreSongs() {
    let queryContext = this.queryContext;
    if (queryContext.hasMoreSongs) {
      if (queryContext.type == 'query' || queryContext.query) {
        queryContext.hasMoreSongsLoading = true;
        this.songsService.searchSongs(queryContext.type, queryContext.query, ++queryContext.songsPage, queryContext.songsLimit).subscribe(songs => {
          songs.forEach(song => queryContext.songs.push({song: song}));
          queryContext.hasMoreSongs = songs.length == queryContext.songsLimit;
          queryContext.hasMoreSongsLoading = false;
        });
      } else if (queryContext.type == 'votes') {
        queryContext.hasMoreSongsLoading = true;
        this.songsService.getSongs(++queryContext.songsPage, queryContext.songsLimit, 'score,desc').subscribe(songs => {
          songs.forEach(song => queryContext.songs.push({song: song}));
          queryContext.hasMoreSongs = songs.length == queryContext.songsLimit;
          queryContext.hasMoreSongsLoading = false;
        });
      }
    }
  }

}

class QueryContext {
  songs: PlaylistSong[] = [];
  songsPage: number = 0;
  songsLimit: number = 10;
  hasMoreSongs: boolean = false;
  hasMoreSongsLoading: boolean = false;
  selection?: CatalogSelection;
  selections: CatalogSelection[] = [];

  constructor(
    public type: string = 'query',
    public query: string = '',
    public loading: boolean = false
  ) {
    if (type != 'query' && query) {
      this.selection = undefined;
    }
  }
}
