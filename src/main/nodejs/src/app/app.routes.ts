import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: 'home', loadComponent: () => import('./home/home.component').then(m => m.HomeComponent) },
  { path: 'login', loadComponent: () => import('./login/login.component').then(m => m.LoginComponent) },
  { path: 'about', loadComponent: () => import('./about/about.component').then(m => m.AboutComponent) },
  { path: 'songs', loadChildren: () => import('./songs/songs.routes').then(m => m.routes) },
  { path: 'playlists', loadChildren: () => import('./playlists/playlists.routes').then(m => m.routes) },
  { path: 'user', loadChildren: () => import('./user/user.routes').then(m => m.routes) },
  { path: '', redirectTo: '/home', pathMatch: 'full' },
];
