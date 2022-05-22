import { NgModule } from '@angular/core';

import { SharedModule } from '../shared/shared.module';
import { PlaylistsRoutingModule } from './playlists-routing.module';
import { PlaylistsComponent } from './playlists.component';
import { PlaylistDetailComponent } from './playlist-detail/playlist-detail.component';

@NgModule({
  declarations: [
    PlaylistsComponent,
    PlaylistDetailComponent
  ],
  imports: [
    SharedModule,
    PlaylistsRoutingModule,
  ]
})
export class PlaylistsModule { }
