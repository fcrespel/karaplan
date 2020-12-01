import { PlaylistSong } from './playlist-song';
import { PlaylistComment } from './playlist-comment';
import { User } from './user';

export class Playlist {
  accessKey: string;
  members: User[];
  songsCount: number;
  songs: PlaylistSong[];
  commentsCount: number;
  comments: PlaylistComment[];
  duration: number;
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;

  // Local field
  isSelected: boolean;

  constructor(
    public id?: number,
    public name?: string,
    public readOnly?: boolean
  ) { }
}
