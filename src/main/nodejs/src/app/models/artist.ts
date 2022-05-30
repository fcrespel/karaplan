import { Song } from './song';

export interface Artist {
  id?: number;
  catalogId: number;
  name: string;
  songs?: Song[];
  createdDate?: Date;
  updatedDate?: Date;
}
