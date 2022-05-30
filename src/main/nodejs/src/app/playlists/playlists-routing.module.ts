import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { PlaylistsComponent } from './playlists.component';
import { PlaylistDetailComponent } from './playlist-detail/playlist-detail.component';

const routes: Routes = [
  { path: '', component: PlaylistsComponent },
  { path: ':id', component: PlaylistDetailComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class PlaylistsRoutingModule { }
