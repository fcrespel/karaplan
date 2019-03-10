import { TestBed } from '@angular/core/testing';

import { SongsService } from './songs.service';

describe('SongsService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: SongsService = TestBed.get(SongsService);
    expect(service).toBeTruthy();
  });
});
