import { Playlist } from './playlist';
import { Song } from './song';
import { User } from './user';

export class PlaylistSong {
  position: number;
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;

  constructor(
    public playlist: Playlist,
    public song: Song
  ) { }
}
