import { Song } from './song';

export class Artist {
  id: number;
  catalogId: number;
  name: string;
  songs: Song[];
  createdDate: Date;
  updatedDate: Date;
}
