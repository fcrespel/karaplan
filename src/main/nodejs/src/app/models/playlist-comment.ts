import { Playlist } from './playlist';
import { User } from './user';

export class PlaylistComment {
  id: number;
  comment: string;
  playlist: Playlist;
  user: User;
  createdDate: Date;
}
