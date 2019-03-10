import { Song } from './song';
import { User } from './user';

export class SongComment {
  id: number;
  comment: string;
  song: Song;
  user: User;
  createdDate: Date;
}
