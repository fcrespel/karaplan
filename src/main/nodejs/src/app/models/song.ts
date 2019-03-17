import { Artist } from './artist';
import { SongVote } from './song-vote';
import { SongComment } from './song-comment';
import { Playlist } from './playlist';
import { User } from './user';

export class Song {
  id: number;
  catalogId: number;
  name: string;
  duration: number;
  image: string;
  lyrics: string;
  artist: Artist;
  votes: SongVote[];
  comments: SongComment[];
  playlists: Playlist[];
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;
  score: number;
  scoreUp: number;
  scoreDown: number;
}
