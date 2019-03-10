import { Artist } from './artist';
import { User } from './user';

export class Song {
  id: number;
  catalogId: number;
  name: string;
  duration: number;
  image: string;
  lyrics: string;
  artist: Artist;
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;
  score: number;
}
