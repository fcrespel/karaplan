import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PlaylistEditModalComponent } from './playlist-edit-modal.component';

describe('PlaylistEditModalComponent', () => {
  let component: PlaylistEditModalComponent;
  let fixture: ComponentFixture<PlaylistEditModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ PlaylistEditModalComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(PlaylistEditModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
