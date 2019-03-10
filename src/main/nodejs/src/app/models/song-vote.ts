import { Song } from './song';
import { User } from './user';

export class SongVote {
    id: number;
    score: number;
    song: Song;
    user: User;
    createdDate: Date;
}
