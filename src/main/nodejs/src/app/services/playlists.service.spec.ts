import { TestBed } from '@angular/core/testing';

import { PlaylistsService } from './playlists.service';

describe('PlaylistsService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: PlaylistsService = TestBed.get(PlaylistsService);
    expect(service).toBeTruthy();
  });
});
