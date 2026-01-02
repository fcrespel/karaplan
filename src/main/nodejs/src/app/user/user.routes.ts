import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'profile', pathMatch: 'full' },
  { path: 'profile', loadComponent: () => import('./user-profile/user-profile.component').then(m => m.UserProfileComponent) },
  { path: 'votes', loadComponent: () => import('./user-votes/user-votes.component').then(m => m.UserVotesComponent) }
];
