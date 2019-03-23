import { Playlist } from './playlist';
import { Song } from './song';

export class PlaylistSong {
  constructor(
    public playlist: Playlist,
    public song: Song
  ) { }
}
