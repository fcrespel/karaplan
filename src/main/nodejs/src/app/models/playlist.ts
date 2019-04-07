import { Song } from './song';
import { User } from './user';

export class Playlist {
  id: number;
  name: string;
  songsCount: number;
  songs: Song[];
  duration: number;
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;
  isSelected: boolean;
  restricted: boolean;
  accessKey: string;
  authorizedUsers: User[];
  readOnly: boolean;
}
