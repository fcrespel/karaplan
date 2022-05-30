export interface CatalogSongFile {
  id: number;
  songId: number;
  artistId: number;
  catalogUrl: string;
  previewUrl: string;
  format: string;
  trackType: string;

  // Local field
  previewStatus?: string;
}
