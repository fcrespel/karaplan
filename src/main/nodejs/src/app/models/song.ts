import { Artist } from './artist';
import { SongVote } from './song-vote';
import { SongComment } from './song-comment';
import { PlaylistSong } from './playlist-song';
import { User } from './user';
import { Style } from './style';

export class Song {
  id: number;
  catalogId: number;
  name: string;
  duration: number;
  year: number;
  image: string;
  lyrics: string;
  rights: string;
  styles: Style[];
  artist: Artist;
  score: number;
  scoreUp: number;
  scoreDown: number;
  votes: SongVote[];
  commentsCount: number;
  comments: SongComment[];
  playlistsCount: number;
  playlists: PlaylistSong[];
  previewUrl: string;
  createdDate: Date;
  createdBy: User;
  updatedDate: Date;
  updatedBy: User;
}
