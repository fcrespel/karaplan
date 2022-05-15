import { Song } from './song';

export interface Style {
  id?: number;
  catalogId: number;
  name: string;
  image?: string;
  songs?: Song[];
}
