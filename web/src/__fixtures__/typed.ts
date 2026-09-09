import campaign from "./campaign.json";
import finding from "./finding.json";
import models from "./models.json";
import runs from "./runs.json";
import type { Campaign, Finding, ModelTarget, Run } from "@/lib/api";

export const campaignFixture = campaign as Campaign;
export const modelFixtures = models as ModelTarget[];
export const findingFixture = finding as Finding;
export const runFixtures = runs as Run[];
