import { Song } from './song';
import { User } from './user';

export interface SongVote {
  id: number;
  score: number;
  song?: Song;
  user?: User;
  createdDate?: Date;
}
