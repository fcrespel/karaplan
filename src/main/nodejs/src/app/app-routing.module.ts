import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { HomeComponent } from './home/home.component';
import { SongsComponent } from './songs/songs.component';
import { PlaylistsComponent } from './playlists/playlists.component';

const routes: Routes = [
  { path: 'home', component: HomeComponent },
  { path: 'songs', component: SongsComponent },
  { path: 'playlists', component: PlaylistsComponent },
  { path: '', redirectTo: '/home', pathMatch: 'full' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
