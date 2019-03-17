import { Song } from './song';
import { User } from './user';

export class Playlist {
  id: number;
  name: string;
  songs: Song[];
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;

  isSelected: boolean;
}
