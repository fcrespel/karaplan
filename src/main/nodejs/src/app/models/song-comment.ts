import { Song } from './song';
import { User } from './user';

export interface SongComment {
  id: number;
  comment: string;
  song?: Song;
  user?: User;
  createdDate?: Date;
}
