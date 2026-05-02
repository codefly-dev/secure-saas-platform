import { ArgocdConfig } from "../config";
import { createArgocd } from "../argocd";

export function createArgocdStack(config: ArgocdConfig) {
  return createArgocd(config);
}
