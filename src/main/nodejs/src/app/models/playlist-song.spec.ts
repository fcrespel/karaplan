import { PlaylistSong } from './playlist-song';

describe('PlaylistSong', () => {
  it('should create an instance', () => {
    expect(new PlaylistSong(null, null)).toBeTruthy();
  });
});
