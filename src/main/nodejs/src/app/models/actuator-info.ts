export class ActuatorInfo {
  build: BuildInfo;
  git: GitInfo;
}

class BuildInfo {
  group: string;
  artifact: string;
  version: string;
  name: string;
  time: Date;
}

class GitInfo {
  commit: GitCommitInfo;
  branch: string;
}

class GitCommitInfo {
  id: string;
  time: Date;
}
