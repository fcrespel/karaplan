import { Playlist } from './playlist';
import { Song } from './song';
import { User } from './user';

export interface PlaylistSong {
  playlist?: Playlist;
  song: Song;
  position?: number;
  createdDate?: Date;
  createdBy?: User;
  updatedDate?: Date;
  updatedBy?: User;
}
