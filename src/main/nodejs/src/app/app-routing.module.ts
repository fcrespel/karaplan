import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { HomeComponent } from './home/home.component';
import { LoginComponent } from './login/login.component';
import { SongsComponent } from './songs/songs.component';
import { SongDetailComponent } from './song-detail/song-detail.component';
import { PlaylistsComponent } from './playlists/playlists.component';
import { UserProfileComponent } from './user-profile/user-profile.component';

const routes: Routes = [
  { path: 'home', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'songs', component: SongsComponent },
  { path: 'songs/:catalogId', component: SongDetailComponent },
  { path: 'playlists', component: PlaylistsComponent },
  { path: 'playlists/:id', component: PlaylistsComponent },
  { path: 'user/profile', component: UserProfileComponent },
  { path: '', redirectTo: '/home', pathMatch: 'full' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
