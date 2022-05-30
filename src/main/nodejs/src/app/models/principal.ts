import { User } from './user';

export interface Principal {
  user: User;
  name: string;
}
