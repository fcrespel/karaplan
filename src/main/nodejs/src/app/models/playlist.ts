import { PlaylistSong } from './playlist-song';
import { PlaylistComment } from './playlist-comment';
import { User } from './user';

export class Playlist {
  id: number;
  name: string;
  readOnly: boolean;
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
  isSelected: boolean;
}
