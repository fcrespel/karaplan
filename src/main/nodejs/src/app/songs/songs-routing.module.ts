import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { SongsComponent } from './songs.component';
import { SongDetailComponent } from './song-detail/song-detail.component';

const routes: Routes = [
  { path: '', component: SongsComponent },
  { path: ':catalogId', component: SongDetailComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class SongsRoutingModule { }
