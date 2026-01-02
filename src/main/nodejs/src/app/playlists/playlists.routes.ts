import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', loadComponent: () => import('./playlists.component').then(m => m.PlaylistsComponent) },
  { path: ':id', loadComponent: () => import('./playlist-detail/playlist-detail.component').then(m => m.PlaylistDetailComponent) }
];
