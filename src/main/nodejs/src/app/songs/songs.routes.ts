import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', loadComponent: () => import('./songs.component').then(m => m.SongsComponent) },
  { path: ':catalogId', loadComponent: () => import('./song-detail/song-detail.component').then(m => m.SongDetailComponent) }
];
