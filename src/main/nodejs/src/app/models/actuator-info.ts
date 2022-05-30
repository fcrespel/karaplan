export interface ActuatorInfo {
  build: BuildInfo;
  git: GitInfo;
}

interface BuildInfo {
  group: string;
  artifact: string;
  version: string;
  name: string;
  time: Date;
}

interface GitInfo {
  commit: GitCommitInfo;
  branch: string;
}

interface GitCommitInfo {
  id: string;
  time: Date;
}
