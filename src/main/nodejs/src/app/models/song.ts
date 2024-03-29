import { Artist } from './artist';
import { SongVote } from './song-vote';
import { SongComment } from './song-comment';
import { PlaylistSong } from './playlist-song';
import { User } from './user';
import { Style } from './style';

export interface Song {
  id?: number;
  catalogId: number;
  name: string;
  duration?: number;
  year?: number;
  image: string;
  rights?: string;
  styles?: Style[];
  artist: Artist;
  score?: number;
  scoreUp?: number;
  scoreDown?: number;
  votes?: SongVote[];
  commentsCount?: number;
  comments?: SongComment[];
  playlistsCount?: number;
  playlists?: PlaylistSong[];
  createdDate?: Date;
  createdBy?: User;
  updatedDate?: Date;
  updatedBy?: User;

  // Local fields
  previewUrl?: string;
  previewStatus?: string;
}
